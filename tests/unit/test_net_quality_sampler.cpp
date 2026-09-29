/**
 * test_net_quality_sampler.cpp — pure helpers of the network-quality sampler
 * (median, throughput delta, and the 4b.3 interval-retransmit-rate window),
 * plus the macOS syscall entry points (`read_net_counters()` /
 * `sample_net_quality()`, both YUZU_EXPORT), which are live-tested below since
 * the macOS suite runs on real macOS runners, and a Linux smoke test of the
 * `/proc/net/dev` counter read (`read_net_counters()`). The Linux netlink
 * INET_DIAG path is verified EMPIRICALLY on the Linux rig (rtt_p50 matches
 * `ss -ti`; the interval rate separates 0%/4%/12% netem loss) and the Windows
 * GetIfTable2 / GetTcpStatisticsEx path is exercised on its own live rig —
 * neither here.
 */
#include "net_quality_sampler.hpp"

#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <optional>

using namespace yuzu::agent::netq;

TEST_CASE("median: middle element, empty → nullopt", "[netq]") {
    CHECK(median({}) == std::nullopt);
    CHECK(median({5.0}) == 5.0);
    CHECK(median({3.0, 1.0, 2.0}) == 2.0);      // sorted 1,2,3 → 2
    CHECK(median({4.0, 1.0, 3.0, 2.0}) == 3.0); // sorted 1,2,3,4 → index 2 = 3
}

TEST_CASE("throughput_bps: delta over interval, wrap-safe", "[netq]") {
    using namespace std::chrono;
    const auto t0 = steady_clock::now();
    const NetCounters prev{true, 1000, 2000, t0};
    const NetCounters cur{true, 1000 + 3000, 2000 + 1000, t0 + seconds(2)}; // +4000 B / 2 s
    const auto bps = throughput_bps(prev, cur);
    REQUIRE(bps.has_value());
    CHECK(*bps == 2000.0);

    // Non-integral quotient — pins DOUBLE division (an integer-division
    // regression would truncate 33333.33… to 33333.0 exactly and still pass an
    // exactly-divisible case like the one above).
    const NetCounters cur3{true, 1000 + 60000, 2000 + 40000, t0 + seconds(3)}; // +100000 B / 3 s
    const auto bps3 = throughput_bps(prev, cur3);
    REQUIRE(bps3.has_value());
    CHECK(*bps3 == Catch::Approx(100000.0 / 3.0));

    // First heartbeat (invalid prev) baselines — no rate.
    CHECK(throughput_bps(NetCounters{}, cur) == std::nullopt);
    // Counter wrap/reset (cur < prev) → nullopt, never a bogus huge/negative rate.
    const NetCounters wrapped{true, 10, 10, t0 + seconds(2)};
    CHECK(throughput_bps(prev, wrapped) == std::nullopt);
    // Zero/negative interval → nullopt.
    const NetCounters same_t{true, 5000, 5000, t0};
    CHECK(throughput_bps(prev, same_t) == std::nullopt);
}

TEST_CASE("RetransWindow: interval delta, not absolute ratio", "[netq]") {
    RetransWindow w;
    // <2 readings → no rate (a single sample can't yield an interval delta).
    CHECK(w.rate_pct() == std::nullopt);
    w.push(1000, 100000); // huge absolute lifetime ratio (1%) baked into totals
    CHECK(w.rate_pct() == std::nullopt);
    // Next interval added 40 retrans over 1000 segments → 4.0% (the INTERVAL
    // rate), independent of the large pre-existing absolute totals.
    w.push(1040, 101000);
    REQUIRE(w.rate_pct().has_value());
    CHECK(*w.rate_pct() == Catch::Approx(4.0));
}

TEST_CASE("RetransWindow: idle interval (no segments advance) → absent, not 0", "[netq]") {
    RetransWindow w;
    w.push(500, 50000);
    w.push(500, 50000); // nothing sent → Δsegs == 0
    CHECK(w.rate_pct() == std::nullopt); // never a fabricated healthy 0%
}

TEST_CASE("RetransWindow: connection-churn delta is clamped at zero", "[netq]") {
    RetransWindow w;
    w.push(900, 100000);
    // A high-retrans connection closed → Σretrans DROPS, but Σsegs still
    // advanced on the survivors. Δretrans must clamp to 0 (never negative loss).
    w.push(300, 101000); // retrans 900→300 (down), segs +1000
    REQUIRE(w.rate_pct().has_value());
    CHECK(*w.rate_pct() == Catch::Approx(0.0)); // clamped, not negative
}

TEST_CASE("RetransWindow: smooths over the window and evicts oldest", "[netq]") {
    RetransWindow w{3}; // cap 3 readings → 2 intervals
    w.push(0, 0);
    w.push(10, 1000);   // interval A: +10/+1000
    w.push(30, 2000);   // interval B: +20/+1000  → window sum 30/2000 = 1.5%
    REQUIRE(w.rate_pct().has_value());
    CHECK(*w.rate_pct() == Catch::Approx(1.5));
    // 4th push evicts the (0,0) reading; window is now the last 3.
    w.push(130, 2500);  // interval C: +100/+500; window = B+C = 120/1500 = 8.0%
    REQUIRE(w.rate_pct().has_value());
    CHECK(*w.rate_pct() == Catch::Approx(8.0));
}

TEST_CASE("RetransWindow: a clean link reads ~0 across the window", "[netq]") {
    RetransWindow w;
    uint64_t segs = 100000;
    for (int i = 0; i < 6; ++i) {
        segs += 5000;        // steady traffic
        w.push(200, segs);   // retrans never advances → clean
    }
    REQUIRE(w.rate_pct().has_value());
    CHECK(*w.rate_pct() == Catch::Approx(0.0)); // no false positive on a clean link
}

TEST_CASE("RetransWindow: counter decrease (DWORD wrap) clamps, never negative", "[netq]") {
    // Windows feeds 32-bit DWORD GetTcpStatisticsEx counters; on a long-uptime busy
    // host dwOutSegs/dwRetransSegs can wrap, so segs (and retrans) may DECREASE
    // between readings. The interval must contribute zero, never a negative/garbage
    // rate. (Distinct from the churn case above, where retrans drops but segs rises.)
    RetransWindow w;
    w.push(1000, 200000);
    w.push(40, 8000);      // both wrapped DOWN (cur < prev) → Δretr<0 and Δsegs<0, both clamped
    CHECK(w.rate_pct() == std::nullopt); // the only interval contributed no segments → absent
    // A subsequent clean interval after the wrap reads correctly (post-wrap baseline).
    w.push(50, 9000);      // +10 retr / +1000 segs → 1.0%
    REQUIRE(w.rate_pct().has_value());
    CHECK(*w.rate_pct() == Catch::Approx(1.0)); // wrap interval excluded, not poisoning the rate
}

// NOTE: the Windows platform reads (GetIfTable2 throughput + GetTcpStatisticsEx
// retransmit counters) are deliberately NOT unit-tested here — like the Linux
// netlink path above, their live syscall path is exercised on its own
// platform's rig, not in this cross-platform file (both `read_net_counters()`
// and `sample_net_quality()` are YUZU_EXPORT on every platform, macOS included
// — see the live macOS smoke tests below, which DO run here). A live rig
// verifies only the COUNTER PLUMBING (the heartbeat ships
// yuzu.net_throughput_bps + net_retrans_pct → yuzu_fleet_net_* gauges); it
// does NOT validate the Windows retransmit signal's separation-under-loss —
// that netem validation was run on Linux only and is tracked for Windows in
// issue #1465. The cross-platform, deterministic helpers above (median /
// throughput_bps / RetransWindow) are unit-tested everywhere.

#ifdef __linux__
// Linux smoke test: read_net_counters() is the /proc/net/dev read path — this
// exercises the fgets + strtoull field walk (which replaced sscanf; glibc 2.38
// __isoc23_* compatibility) end-to-end on the live procfs, mirroring the macOS
// smoke test below.
TEST_CASE("Linux: read_net_counters parses /proc/net/dev and finds live traffic",
          "[netq][linux]") {
    const NetCounters c = read_net_counters();
    // A successful walk always sets valid=true (headers skipped, lines walked).
    REQUIRE(c.valid);
    // Every real Linux CI host has at least one non-loopback interface with
    // since-boot traffic, so this forces the field walk to have actually
    // converted the rx/tx byte counters — it fails if the parse always misses.
    CHECK(c.rx_bytes + c.tx_bytes > 0);
}
#endif

#ifdef __APPLE__
// macOS smoke test: read_net_counters() is the NET_RT_IFLIST2 syscall path, so
// this exercises the live routing-socket walk on this host rather than a pure
// helper (mirrors the intent of the Linux/Windows live-rig notes above, but as
// an automated CI check since the macOS suite runs on real macOS runners).
TEST_CASE("macOS: read_net_counters walks NET_RT_IFLIST2 and finds live traffic",
          "[netq][macos]") {
    const NetCounters c = read_net_counters();
    // A successful walk always sets valid=true (even a quiescent host has
    // interfaces to enumerate); this forces the sysctl + bounds-checked walk to
    // actually run end-to-end, not just compile.
    REQUIRE(c.valid);
    // Every real macOS host has at least one non-loopback interface with
    // since-boot traffic, so this forces the walk to have found and summed a
    // real RTM_IFINFO2 message — the test fails if the NET_RT_IFLIST2 path is
    // broken (e.g. always skipping/mis-parsing messages).
    CHECK(c.rx_bytes + c.tx_bytes > 0);
}

TEST_CASE("macOS: sample_net_quality omits retransmit and RTT (deferred in v1)",
          "[netq][macos]") {
    const NetCounters c1 = read_net_counters();
    const NetCounters c2 = read_net_counters();
    const NetQualitySample s = sample_net_quality(c1, c2);
    // Both are deferred on macOS in v1 — absent, never a fabricated false/0.
    // Deliberately NOT asserting throughput_bps>0: a quiescent interval between
    // c1/c2 is legitimately absent (throughput_valid may be true or false).
    CHECK_FALSE(s.rtt_valid);
    CHECK_FALSE(s.retrans_valid);
}

TEST_CASE("macOS: sample_net_quality computes throughput_bps deterministically",
          "[netq][macos]") {
    using namespace std::chrono;
    const auto t0 = steady_clock::now();
    const NetCounters c1{true, 1000, 1000, t0};
    const NetCounters c2{true, 51000, 26000, t0 + seconds(1)};
    const NetQualitySample s = sample_net_quality(c1, c2);
    // Mirrors throughput_bps's own arithmetic (see the cross-platform test
    // above): (51000-1000) + (26000-1000) = 75000 bytes over 1 s.
    REQUIRE(s.throughput_valid);
    CHECK(s.throughput_bps == Catch::Approx(75000.0));
    // macOS still omits both in v1 — deterministic, not just "may be false".
    CHECK_FALSE(s.rtt_valid);
    CHECK_FALSE(s.retrans_valid);
}
#endif
