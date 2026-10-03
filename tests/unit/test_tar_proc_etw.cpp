// Tests for tar_proc_etw — the ETW process collector's deterministic parts.
// The live ETW session (start/decode/user-resolution) needs an elevated real
// session and is exercised by the standalone harness + agent UAT, not here; what
// IS unit-testable is the bounded ring buffer (the push→pull bridge) and the
// no-op contract before start / off-Windows.

#include "tar_proc_etw.hpp"

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdio>
#include <fstream>

using yuzu::tar::ProcEtwCollector;
using yuzu::tar::ProcEvent;
using yuzu::tar::ProcEventRing;

TEST_CASE("ProcEventRing buffers and drains in order", "[tar][procetw]") {
    ProcEventRing ring(4);
    ProcEvent a;
    a.pid = 11;
    a.is_start = true;
    a.image_name = "a.exe";
    ProcEvent b;
    b.pid = 22;
    b.is_start = false;
    b.exit_code = 3;

    REQUIRE(ring.push(a));
    REQUIRE(ring.push(b));

    auto out = ring.drain();
    REQUIRE(out.size() == 2);
    REQUIRE(out[0].pid == 11);
    REQUIRE(out[0].is_start);
    REQUIRE(out[0].image_name == "a.exe");
    REQUIRE(out[1].pid == 22);
    REQUIRE_FALSE(out[1].is_start);
    REQUIRE(out[1].exit_code == 3);
    REQUIRE(ring.dropped() == 0);
}

TEST_CASE("ProcEventRing drain empties the buffer", "[tar][procetw]") {
    ProcEventRing ring(8);
    REQUIRE(ring.push(ProcEvent{}));
    REQUIRE(ring.drain().size() == 1);
    REQUIRE(ring.drain().empty()); // nothing left after the first drain
}

TEST_CASE("ProcEventRing drops on overflow and counts the drops", "[tar][procetw]") {
    ProcEventRing ring(2);
    REQUIRE(ring.push(ProcEvent{}));
    REQUIRE(ring.push(ProcEvent{}));
    REQUIRE_FALSE(ring.push(ProcEvent{})); // full → dropped
    REQUIRE_FALSE(ring.push(ProcEvent{})); // full → dropped
    REQUIRE(ring.dropped() == 2);

    auto out = ring.drain();
    REQUIRE(out.size() == 2); // only the first two were retained

    // Draining frees capacity; the drop counter persists across drains.
    REQUIRE(ring.push(ProcEvent{}));
    REQUIRE(ring.dropped() == 2);
}

TEST_CASE("ProcEventRing clamps a zero capacity to one", "[tar][procetw]") {
    ProcEventRing ring(0); // 0 is meaningless (every push would drop); clamped to 1
    REQUIRE(ring.capacity() == 1);
    REQUIRE(ring.push(ProcEvent{}));       // holds one
    REQUIRE_FALSE(ring.push(ProcEvent{})); // full → dropped, NOT drop-everything
    REQUIRE(ring.dropped() == 1);
    REQUIRE(ring.drain().size() == 1);
}

TEST_CASE("ProcEventRing drop counter accumulates across overflow cycles", "[tar][procetw]") {
    ProcEventRing ring(1);
    REQUIRE(ring.push(ProcEvent{}));
    REQUIRE_FALSE(ring.push(ProcEvent{})); // dropped #1
    REQUIRE(ring.drain().size() == 1);
    REQUIRE(ring.push(ProcEvent{}));       // capacity freed by the drain
    REQUIRE_FALSE(ring.push(ProcEvent{})); // dropped #2
    REQUIRE(ring.dropped() == 2);          // monotonic across drains
}

TEST_CASE("ProcEtwCollector yields nothing before start", "[tar][procetw]") {
    ProcEtwCollector c(16);
    REQUIRE_FALSE(c.running());
    REQUIRE(c.drain().empty());
    REQUIRE(c.dropped() == 0);
    c.stop(); // safe to call when never started
}

TEST_CASE("ProcEtwCollector stop is idempotent; drain-after-stop is empty", "[tar][procetw]") {
    ProcEtwCollector c(8);
    c.stop(); // stop before any start
    c.stop(); // double stop — must not crash
    REQUIRE_FALSE(c.running());
    REQUIRE(c.drain().empty());
}

TEST_CASE("boot_time_unix is minute-aligned", "[tar][procetw]") {
    const auto b = yuzu::tar::boot_time_unix();
    REQUIRE(b % 60 == 0); // rounded to the minute so it is a stable per-boot key
#ifdef _WIN32
    REQUIRE(b > 0); // a real boot instant on Windows
#else
    REQUIRE(b == 0); // no boot concept off-Windows (backfill is a no-op there)
#endif
}

TEST_CASE("backfill_proc_events_from_etl rejects missing/garbage input without crashing",
          "[tar][procetw]") {
    // Empty path → immediate no-op.
    REQUIRE(yuzu::tar::backfill_proc_events_from_etl("", 0).empty());

    // Non-existent file → OpenTrace fails, no events (off-Windows: a no-op stub).
    const std::string missing = yuzu::test::unique_temp_path("yuzu_test_tar_no_etl_").string();
    REQUIRE(yuzu::tar::backfill_proc_events_from_etl(missing, 1'000'000'000LL).empty());

    // A real file that is NOT a valid .etl (corrupt/torn trace) → the replay must
    // fail cleanly and return empty, never crash (the data dir is writable by the
    // service account, so a malformed file is a reachable input).
    const std::string garbage = yuzu::test::unique_temp_path("yuzu_test_tar_garbage_").string();
    {
        std::ofstream f(garbage, std::ios::binary);
        f << "this is not a valid ETL trace file";
    }
    REQUIRE(yuzu::tar::backfill_proc_events_from_etl(garbage, 1'000'000'000LL).empty());
    std::remove(garbage.c_str());
}

#ifndef _WIN32
TEST_CASE("ProcEtwCollector is a clean no-op off-Windows", "[tar][procetw]") {
    ProcEtwCollector c;
    REQUIRE_FALSE(c.start()); // no ETW outside Windows
    REQUIRE_FALSE(c.running());
    REQUIRE(c.drain().empty());
    c.stop();
}
#endif
