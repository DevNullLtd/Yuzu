/**
 * test_tar_perf.cpp — perf sampling for the TAR edge warehouse (BRD A1).
 *
 * Two halves:
 *  1. derive_sample (pure): the cumulative-counter → rate/percentage math —
 *     CPU busy %, memory/commit %, disk throughput + per-IO latency, network
 *     rates — including the degradation contract (CPU regression invalidates
 *     the sample; disk/net regression zeroes only its own domain).
 *  2. Schema-registry pins: the perf source's tables exist, translate, are
 *     operator-queryable, roll up hourly, and carry time-based retention.
 *
 * The Win32 counter reads are the impure shell, exercised on a live box; the
 * rest runs on every host.
 */

#include "tar_collectors.hpp" // kCollectStatus* — the operator-facing token contract
#include "tar_perf.hpp"
#include "tar_schema_registry.hpp"

#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>
#include <string_view>

using namespace yuzu::tar;
using Catch::Approx;

namespace {

// A baseline reading at t=1000 with all counters at comfortable values.
PerfCounters baseline() {
    PerfCounters c;
    c.valid = true;
    c.disk_valid = true;
    c.net_valid = true;
    c.ts_epoch = 1000;
    c.cpu_idle = 1'000'000'000;
    c.cpu_kernel = 1'500'000'000; // includes idle
    c.cpu_user = 500'000'000;
    c.mem_total_bytes = 16ULL << 30;
    c.mem_avail_bytes = 4ULL << 30;
    c.commit_total_bytes = 10ULL << 30;
    c.commit_limit_bytes = 20ULL << 30;
    c.disk_read_bytes = 1'000'000;
    c.disk_write_bytes = 2'000'000;
    c.disk_read_time_100ns = 10'000'000;
    c.disk_write_time_100ns = 20'000'000;
    c.disk_reads = 1000;
    c.disk_writes = 2000;
    c.net_rx_bytes = 5'000'000;
    c.net_tx_bytes = 6'000'000;
    return c;
}

} // namespace

TEST_CASE("perf: invalid inputs and zero elapsed never derive", "[tar][perf]") {
    PerfCounters good = baseline();
    CHECK(!derive_sample(PerfCounters{}, good).valid);
    CHECK(!derive_sample(good, PerfCounters{}).valid);
    PerfCounters same_ts = good;
    CHECK(!derive_sample(good, same_ts).valid); // elapsed == 0
}

TEST_CASE("perf: normal 30 s derivation", "[tar][perf]") {
    PerfCounters prev = baseline();
    PerfCounters cur = prev;
    cur.ts_epoch = 1030;
    // 30 s on (say) 2 cores: total delta = 600e6 (100 ns units of CPU-time),
    // idle delta = 300e6 → 50% busy.
    cur.cpu_idle += 300'000'000;
    cur.cpu_kernel += 400'000'000; // kernel includes the idle delta
    cur.cpu_user += 200'000'000;
    // 12 GiB of 16 GiB in use; commit unchanged at 50%.
    cur.mem_avail_bytes = 4ULL << 30;
    // Disk: +30 MB read over 30 s = 1 MB/s; +3000 reads taking +3e6 ×100 ns
    // total → 1000 ×100 ns = 100 µs per read. Writes idle.
    cur.disk_read_bytes += 30'000'000;
    cur.disk_reads += 3000;
    cur.disk_read_time_100ns += 3'000'000;
    // Net: +3 MB rx, +1.5 MB tx over 30 s.
    cur.net_rx_bytes += 3'000'000;
    cur.net_tx_bytes += 1'500'000;

    auto s = derive_sample(prev, cur);
    REQUIRE(s.valid);
    CHECK(s.cpu_pct == Approx(50.0));
    CHECK(s.mem_used_pct == Approx(75.0));
    CHECK(s.commit_pct == Approx(50.0));
    CHECK(s.disk_read_bps == 1'000'000);
    CHECK(s.disk_write_bps == 0);
    CHECK(s.disk_read_lat_us == 100); // 3e6 / 3000 reads / 10 = 100 µs per read
    CHECK(s.disk_write_lat_us == 0);  // no writes → no latency claim
    CHECK(s.net_rx_bps == 100'000);
    CHECK(s.net_tx_bps == 50'000);
}

TEST_CASE("perf: CPU counter regression invalidates the whole sample", "[tar][perf]") {
    PerfCounters prev = baseline();
    PerfCounters cur = prev;
    cur.ts_epoch = 1030;
    cur.cpu_kernel -= 1; // reboot / counter reset
    CHECK(!derive_sample(prev, cur).valid);
}

TEST_CASE("perf: disk regression zeroes the disk domain only", "[tar][perf]") {
    PerfCounters prev = baseline();
    PerfCounters cur = prev;
    cur.ts_epoch = 1030;
    cur.cpu_kernel += 100'000'000;
    cur.cpu_idle += 100'000'000;
    cur.disk_read_bytes = 0; // hotplug — counters reset below the baseline
    cur.disk_reads = 0;
    cur.net_rx_bytes += 300'000;

    auto s = derive_sample(prev, cur);
    REQUIRE(s.valid); // the sample survives
    CHECK(s.disk_read_bps == 0);
    CHECK(s.disk_read_lat_us == 0);
    CHECK(s.net_rx_bps == 10'000); // the other domains stay honest
}

TEST_CASE("perf: missing disk support leaves disk fields zero", "[tar][perf]") {
    PerfCounters prev = baseline();
    PerfCounters cur = prev;
    cur.ts_epoch = 1030;
    prev.disk_valid = false; // IOCTL_DISK_PERFORMANCE unavailable
    cur.disk_read_bytes += 30'000'000;
    auto s = derive_sample(prev, cur);
    REQUIRE(s.valid);
    CHECK(s.disk_read_bps == 0);
}

TEST_CASE("perf: a net-invalid reading degrades the net domain, never spikes it",
          "[tar][perf]") {
    // Tick N's interface enumeration failed (net_valid=false, counters 0) and
    // became the baseline. Tick N+1 reads normally with large since-boot
    // totals: without the net guard the delta(0, since-boot) would record a
    // massive false rate. The guard must zero the domain for exactly the
    // intervals adjacent to the failed reading.
    PerfCounters failed = baseline();
    failed.ts_epoch = 1030;
    failed.net_valid = false;
    failed.net_rx_bytes = 0;
    failed.net_tx_bytes = 0;
    failed.cpu_idle += 100'000'000;
    failed.cpu_kernel += 150'000'000;
    failed.cpu_user += 50'000'000;

    PerfCounters recovered = baseline();
    recovered.ts_epoch = 1060;
    recovered.net_rx_bytes = 500'000'000'000; // cumulative since boot
    recovered.net_tx_bytes = 200'000'000'000;
    recovered.cpu_idle += 200'000'000;
    recovered.cpu_kernel += 300'000'000;
    recovered.cpu_user += 100'000'000;

    auto during = derive_sample(baseline(), failed);
    REQUIRE(during.valid); // the rest of the row stays honest
    CHECK(during.net_rx_bps == 0);
    auto after = derive_sample(failed, recovered);
    REQUIRE(after.valid);
    CHECK(after.net_rx_bps == 0); // NOT delta(0, 5e11)/30 ≈ 16 GB/s
    CHECK(after.net_tx_bps == 0);
}

TEST_CASE("perf: percentages are clamped against garbage readings", "[tar][perf]") {
    PerfCounters prev = baseline();
    PerfCounters cur = prev;
    cur.ts_epoch = 1030;
    cur.cpu_kernel += 100;
    cur.mem_avail_bytes = 32ULL << 30;            // avail > total
    cur.commit_total_bytes = 40ULL << 30;         // commit > limit
    auto s = derive_sample(prev, cur);
    REQUIRE(s.valid);
    CHECK(s.mem_used_pct == 0.0);
    CHECK(s.commit_pct == 100.0);
}

TEST_CASE("perf: live counter read smoke", "[tar][perf]") {
#if defined(_WIN32) || defined(__linux__)
    // Real syscalls on a real box: the core reads must succeed everywhere.
    // Deliberately NO disk/net assertions — a containerized CI runner may
    // expose zero whole-disk rows; per-domain degrade is the designed behavior.
    auto c = read_perf_counters();
    REQUIRE(c.valid);
    CHECK(c.mem_total_bytes > 0);
#if defined(_WIN32)
    CHECK(c.cpu_kernel > 0); // GetSystemTimes kernel incl. idle — never zero live
#else
    CHECK(c.cpu_user + c.cpu_kernel > 0); // busy + idle jiffies — never zero live
#endif
#else
    CHECK(!read_perf_counters().valid); // kPlanned platforms record nothing
#endif
}

// ── Linux /proc parsing (pure — runs on every host) ──────────────────────────

namespace {

// Aggregate cpu line: user=10000 nice=500 system=3000 idle=80000 iowait=2000
// irq=100 softirq=400 steal=300 (guest fields excluded by the core parser)
// → total=96300, idle=idle+iowait=82000, busy=14300.
constexpr std::string_view kLinuxStat =
    "cpu  10000 500 3000 80000 2000 100 400 300 0 0\n"
    "cpu0 5000 250 1500 40000 1000 50 200 150 0 0\n"
    "intr 12345678\n";

constexpr std::string_view kLinuxMeminfo =
    "MemTotal:       16384000 kB\n"
    "MemFree:         2048000 kB\n"
    "MemAvailable:    8192000 kB\n"
    "Buffers:          123456 kB\n"
    "CommitLimit:    12000000 kB\n"
    "Committed_AS:    9000000 kB\n";

// Whole disks sda + nvme0n1 count; the partition/pseudo/aggregate rows must
// all be excluded (sda1, nvme0n1p1, loop0, dm-0).
constexpr std::string_view kLinuxDiskstats =
    "   8       0 sda 5000 100 200000 4000 3000 50 100000 6000 0 5000 10000\n"
    "   8       1 sda1 4900 100 199000 3900 2900 50 99000 5900 0 4900 9800\n"
    " 259       0 nvme0n1 1000 0 50000 500 2000 0 80000 900 0 700 1400\n"
    " 259       1 nvme0n1p1 900 0 49000 450 1900 0 79000 850 0 650 1300\n"
    "   7       0 loop0 10 0 80 5 0 0 0 0 0 5 5\n"
    " 253       0 dm-0 5900 0 249000 4350 4900 0 179000 6850 0 5600 11200\n";

// lo excluded; virtual interfaces (docker0) deliberately included.
constexpr std::string_view kLinuxNetDev =
    "Inter-|   Receive                                                |  Transmit\n"
    " face |bytes    packets errs drop fifo frame compressed multicast|bytes    "
    "packets errs drop fifo colls carrier compressed\n"
    "    lo: 1000000    9999    0    0    0     0          0         0  1000000  "
    "  9999    0    0    0     0       0          0\n"
    "  eth0: 5000000   40000    0    0    0     0          0         0  2500000  "
    " 30000    0    0    0     0       0          0\n"
    "docker0:  700000    5000    0    0    0     0          0         0   300000 "
    "   2000    0    0    0     0       0          0\n";

} // namespace

TEST_CASE("perf: Linux /proc parse — field mapping and unit conversions",
          "[tar][perf][linux]") {
    auto c = parse_linux_perf_counters(kLinuxStat, kLinuxMeminfo, kLinuxDiskstats, kLinuxNetDev,
                                       "0\n", 1234);
    REQUIRE(c.valid);
    CHECK(c.ts_epoch == 1234);
    // CPU mapping: idle+iowait lands in idle AND kernel; busy in user — so
    // derive_sample's total = kernel + user and busy = total − idle hold.
    CHECK(c.cpu_idle == 82000);
    CHECK(c.cpu_kernel == 82000);
    CHECK(c.cpu_user == 14300);
    // kB → bytes; MemAvailable preferred over MemFree.
    CHECK(c.mem_total_bytes == 16384000ULL * 1024);
    CHECK(c.mem_avail_bytes == 8192000ULL * 1024);
    CHECK(c.commit_total_bytes == 9000000ULL * 1024);
    CHECK(c.commit_limit_bytes == 12000000ULL * 1024);
    // Whole disks only: sda + nvme0n1; sectors are the fixed 512-byte ABI
    // unit; io ticks ms ×10'000 into the 100 ns fields.
    REQUIRE(c.disk_valid);
    CHECK(c.disk_reads == 6000);
    CHECK(c.disk_writes == 5000);
    CHECK(c.disk_read_bytes == 250000ULL * 512);
    CHECK(c.disk_write_bytes == 180000ULL * 512);
    CHECK(c.disk_read_time_100ns == 4500ULL * 10'000);
    CHECK(c.disk_write_time_100ns == 6900ULL * 10'000);
    // lo excluded from the sums but still proves netdev content was seen.
    CHECK(c.net_valid);
    CHECK(c.net_rx_bytes == 5'700'000);
    CHECK(c.net_tx_bytes == 2'800'000);
}

TEST_CASE("perf: Linux parse — memory fallback, overcommit gate, degrade paths",
          "[tar][perf][linux]") {
    SECTION("MemAvailable absent falls back to MemFree (kernel < 3.14)") {
        auto c = parse_linux_perf_counters(
            kLinuxStat, "MemTotal: 1000 kB\nMemFree: 400 kB\n", "", "", "0\n", 1);
        REQUIRE(c.valid);
        CHECK(c.mem_avail_bytes == 400ULL * 1024);
    }
    SECTION("vm.overcommit_memory=1 zeroes commit — the ratio is advisory there") {
        auto c = parse_linux_perf_counters(kLinuxStat, kLinuxMeminfo, "", "", "1\n", 1);
        REQUIRE(c.valid);
        CHECK(c.commit_total_bytes == 0);
        CHECK(c.commit_limit_bytes == 0); // derive_sample records commit_pct 0.0
    }
    SECTION("missing MemTotal invalidates the reading (core read)") {
        auto c = parse_linux_perf_counters(kLinuxStat, "MemFree: 400 kB\n", "", "", "0\n", 1);
        CHECK(!c.valid);
    }
    SECTION("non-numeric MemTotal token invalidates the reading — never half-parses") {
        auto c = parse_linux_perf_counters(kLinuxStat, "MemTotal: abc kB\n", "", "", "0\n", 1);
        CHECK(!c.valid);
    }
    SECTION("empty overcommit payload (masked /proc/sys) keeps commit populated") {
        // The Linux shell feeds "" when the file is unreadable; anything that
        // is not exactly "1" reads as not-always — fail-safe toward keeping
        // the signal.
        auto c = parse_linux_perf_counters(kLinuxStat, kLinuxMeminfo, "", "", "", 1);
        REQUIRE(c.valid);
        CHECK(c.commit_total_bytes == 9000000ULL * 1024);
        CHECK(c.commit_limit_bytes == 12000000ULL * 1024);
    }
    SECTION("MemAvailable AND MemFree both absent: avail 0 (reads as 100% used) — deliberate") {
        auto c = parse_linux_perf_counters(kLinuxStat, "MemTotal: 1000 kB\n", "", "", "0\n", 1);
        REQUIRE(c.valid);
        CHECK(c.mem_avail_bytes == 0);
    }
    SECTION("loopback-only netdev still sets net_valid — content was seen, sums stay 0") {
        auto c = parse_linux_perf_counters(
            kLinuxStat, kLinuxMeminfo, "",
            "h1\nh2\n    lo: 1000 1 0 0 0 0 0 0 1000 1 0 0 0 0 0 0\n", "0\n", 1);
        REQUIRE(c.valid);
        CHECK(c.net_valid); // the false-spike guard depends on exactly this
        CHECK(c.net_rx_bytes == 0);
    }
    SECTION("a diskstats row with exactly 11 fields is accepted") {
        auto c = parse_linux_perf_counters(kLinuxStat, kLinuxMeminfo,
                                           "8 0 sda 100 0 2000 30 50 0 1000 20\n", "", "0\n", 1);
        REQUIRE(c.valid);
        REQUIRE(c.disk_valid);
        CHECK(c.disk_reads == 100);
        CHECK(c.disk_write_time_100ns == 20ULL * 10'000);
    }
    SECTION("malformed /proc/stat invalidates the reading (core read)") {
        auto c = parse_linux_perf_counters("garbage\n", kLinuxMeminfo, "", "", "0\n", 1);
        CHECK(!c.valid);
    }
    SECTION("empty diskstats/netdev degrade their own domain only") {
        auto c = parse_linux_perf_counters(kLinuxStat, kLinuxMeminfo, "", "", "0\n", 1);
        REQUIRE(c.valid);
        CHECK(!c.disk_valid);
        CHECK(!c.net_valid); // no netdev content seen — domain must degrade
        CHECK(c.net_rx_bytes == 0);
    }
    SECTION("a corrupt numeric token rejects the whole diskstats row") {
        // "4x000" must not half-parse as 4 — that would regress the time
        // counter and poison the next interval's latency.
        auto c = parse_linux_perf_counters(
            kLinuxStat, kLinuxMeminfo,
            "   8 0 sda 5000 100 200000 4x000 3000 50 100000 6000 0 5000 10000\n", "", "0\n", 1);
        REQUIRE(c.valid);
        CHECK(!c.disk_valid); // the only row was rejected
    }
    SECTION("CR-bearing / truncated CRLF payloads are skipped, never wedge the scan") {
        // A '\r' used to stall split_ws's token walk forever (livelock on the
        // collect tick). These must complete and simply treat the content as
        // absent/malformed.
        auto c = parse_linux_perf_counters(kLinuxStat, "MemTotal:\r\n",
                                           "8 0 sda 1 2\r\n", " eth0: 1 2\r\n", "0\n", 1);
        CHECK(!c.valid);      // meminfo carried no value
        CHECK(!c.disk_valid); // truncated row skipped
        CHECK(!c.net_valid);  // truncated row skipped
        auto crlf = parse_linux_perf_counters(
            "cpu  10000 500 3000 80000 2000 100 400 300 0 0\r\n",
            "MemTotal: 1000 kB\r\nMemAvailable: 400 kB\r\n", "", "", "0\r\n", 1);
        REQUIRE(crlf.valid); // CRLF content parses normally
        CHECK(crlf.mem_total_bytes == 1000ULL * 1024);
        CHECK(crlf.cpu_idle == 82000);  // CR never contaminates the CPU fields
        CHECK(crlf.cpu_user == 14300);
    }
}

TEST_CASE("perf: Linux end-to-end — two parsed instants through derive_sample",
          "[tar][perf][linux]") {
    // Instant A: user=10000 system=5000 idle=80000 iowait=2000 irq=500
    // softirq=500 steal=1000 → total=99000, idle=82000.
    // Instant B, 30 s later: user+1000 system+500 idle+1200 iowait+800
    // steal+500 → Δtotal=4000, Δidle=2000, Δbusy=2000 → 50% CPU. The moving
    // iowait proves it reads as idle; the moving steal proves it reads as busy.
    const std::string_view stat_a = "cpu  10000 0 5000 80000 2000 500 500 1000 0 0\n";
    const std::string_view stat_b = "cpu  11000 0 5500 81200 2800 500 500 1500 0 0\n";
    const std::string_view mem_a = "MemTotal: 16384000 kB\nMemAvailable: 8192000 kB\n"
                                   "Committed_AS: 6000000 kB\nCommitLimit: 12000000 kB\n";
    const std::string_view mem_b = "MemTotal: 16384000 kB\nMemAvailable: 4096000 kB\n"
                                   "Committed_AS: 6000000 kB\nCommitLimit: 12000000 kB\n";
    // Δreads=3000 over Δ300 ms → 100 µs/IO; Δrd_sectors=60000 ×512 /30 s →
    // 1'024'000 B/s. Δwrites=1000 over Δ250 ms → 250 µs/IO; Δwr_sectors=30000
    // → 512'000 B/s.
    const std::string_view disk_a = "   8 0 sda 1000 0 100000 1000 500 0 50000 500 0 900 1500\n";
    const std::string_view disk_b = "   8 0 sda 4000 0 160000 1300 1500 0 80000 750 0 1200 2050\n";
    const std::string_view net_a = "h1\nh2\n eth0: 1000000 1 0 0 0 0 0 0 2000000 1 0 0 0 0 0 0\n";
    const std::string_view net_b = "h1\nh2\n eth0: 4000000 2 0 0 0 0 0 0 3500000 2 0 0 0 0 0 0\n";

    const auto prev = parse_linux_perf_counters(stat_a, mem_a, disk_a, net_a, "0\n", 1000);
    const auto cur = parse_linux_perf_counters(stat_b, mem_b, disk_b, net_b, "0\n", 1030);
    REQUIRE(prev.valid);
    REQUIRE(cur.valid);

    const auto s = derive_sample(prev, cur);
    REQUIRE(s.valid);
    CHECK(s.cpu_pct == Approx(50.0));
    CHECK(s.mem_used_pct == Approx(75.0));
    CHECK(s.commit_pct == Approx(50.0));
    CHECK(s.disk_read_bps == 1'024'000);
    CHECK(s.disk_write_bps == 512'000);
    CHECK(s.disk_read_lat_us == 100);
    CHECK(s.disk_write_lat_us == 250);
    CHECK(s.net_rx_bps == 100'000);
    CHECK(s.net_tx_bps == 50'000);
}

TEST_CASE("perf: collect-status tokens are a pinned operator contract", "[tar][perf]") {
    // The emit sites in tar_plugin.cpp use these constants, so together with
    // this pin the documented tokens (yaml-dsl-spec.md tar.collect_perf;
    // operator dashboards parse them) cannot drift silently — renaming one is
    // a deliberate contract change that must update doc + pin together.
    CHECK(kCollectStatusSourceDisabled == "source_disabled");
    CHECK(kCollectStatusUnsupportedPlatform == "unsupported_platform");
    CHECK(kCollectStatusCountersUnavailable == "counters_unavailable");
    CHECK(kCollectStatusBaseline == "baseline");
    CHECK(kCollectStatusSampleRecorded == "sample_recorded");
    CHECK(kCollectStatusAppsRecorded == "apps_recorded");
}

TEST_CASE("perf: a failed counter read maps to a token by registry support (#1846)",
          "[tar][perf]") {
    // Supported OS whose read failed -> counters_unavailable; no collector on the
    // OS (planned/unsupported/unknown) -> unsupported_platform.
    CHECK(read_failure_token(OsSupportStatus::kSupported) == "counters_unavailable");
    CHECK(read_failure_token(OsSupportStatus::kSupportedConstrained) == "counters_unavailable");
    CHECK(read_failure_token(OsSupportStatus::kPlanned) == "unsupported_platform");
    CHECK(read_failure_token(OsSupportStatus::kUnsupported) == "unsupported_platform");
    CHECK(read_failure_token(std::nullopt) == "unsupported_platform");
}

// ── Schema registry pins ─────────────────────────────────────────────────────

TEST_CASE("perf: registry tables translate and are operator-queryable", "[tar][perf]") {
    auto live = translate_dollar_name("$Perf_Live");
    REQUIRE(live);
    CHECK(*live == "perf_live");
    auto hourly = translate_dollar_name("$Perf_Hourly");
    REQUIRE(hourly);
    CHECK(*hourly == "perf_hourly");
    CHECK(is_queryable_table("perf_live"));
    CHECK(is_queryable_table("perf_hourly"));

    auto cols = columns_for_table("perf_live");
    CHECK(std::find(cols.begin(), cols.end(), "cpu_pct") != cols.end());
    CHECK(std::find(cols.begin(), cols.end(), "net_tx_bps") != cols.end());
}

TEST_CASE("perf: hourly rollup SQL exists and targets perf_hourly", "[tar][perf]") {
    auto sql = rollup_sql("perf", "hourly");
    REQUIRE(!sql.empty());
    CHECK(sql.find("INSERT INTO perf_hourly") != std::string::npos);
    CHECK(sql.find("MAX(cpu_pct)") != std::string::npos);
}

TEST_CASE("perf: live retention is time-based", "[tar][perf]") {
    auto sql = retention_sql("perf_live", 2'000'000);
    REQUIRE(!sql.empty());
    CHECK(sql.find("DELETE FROM perf_live WHERE ts <") != std::string::npos);
}

TEST_CASE("perf: DDL declares the perf tables with numeric defaults", "[tar][perf]") {
    auto ddl = generate_warehouse_ddl();
    CHECK(ddl.find("CREATE TABLE IF NOT EXISTS perf_live") != std::string::npos);
    CHECK(ddl.find("CREATE TABLE IF NOT EXISTS perf_hourly") != std::string::npos);
    // REAL columns must default 0, not '' (generator fix shipped with A1).
    CHECK(ddl.find("cpu_pct REAL NOT NULL DEFAULT 0") != std::string::npos);
}

TEST_CASE("perf #538: a reset baseline (post-disable) emits no off-period-spanning row",
          "[tar][perf][source-lifecycle]") {
    // When `perf` is disabled, do_collect_perf's disable branch installs a
    // default-constructed PerfCounters as prev_perf_ (valid=false). This models
    // the first tick AFTER a re-enable: even though the live counters advanced a
    // lot during the paused window, deriving against the reset baseline must
    // produce NO sample (it re-baselines), so the first post-re-enable row never
    // covers the off-period. Without the reset, prev_perf_ would still hold the
    // pre-disable reading and this same call would emit a delta spanning the gap.
    PerfCounters after_gap = baseline();
    after_gap.ts_epoch = 100'000;             // long pause elapsed
    after_gap.cpu_idle += 50'000'000'000;     // counters advanced across the gap
    after_gap.cpu_kernel += 80'000'000'000;
    after_gap.cpu_user += 30'000'000'000;
    after_gap.disk_read_bytes += 9'000'000'000;
    after_gap.net_rx_bytes += 9'000'000'000;

    // The disable branch's reset == a default-constructed prev → no row.
    CHECK(!derive_sample(PerfCounters{}, after_gap).valid);
    // Sanity: against the real pre-gap baseline it WOULD have emitted a row —
    // exactly the off-period leak the reset prevents.
    CHECK(derive_sample(baseline(), after_gap).valid);
}
