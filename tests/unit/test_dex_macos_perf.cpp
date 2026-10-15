/**
 * test_dex_macos_perf.cpp — dex_macos_perf.hpp's pure math (every host) + the six
 * darwin-only readers (host_statistics/host_statistics64/IOKit/sysctlbyname), pinned
 * live against this box, `SKIP()`d where the live environment has nothing to read
 * (e.g. a VM runner with no IOBlockStorageDriver rows).
 *
 * Nothing in dex_macos_perf.{hpp,cpp} is wired into any collector yet (C0 goal:
 * primitives only) — these tests pin the primitives directly, not a consumer.
 */

#include "dex_macos_perf.hpp"

#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <limits>

#if defined(__APPLE__)
#include <yuzu/agent/scoped_cfref.hpp>
#include <yuzu/agent/scoped_ioobject.hpp>

#include <IOKit/IOKitLib.h>
#include <IOKit/storage/IOBlockStorageDriver.h>
#include <sys/sysctl.h>

#include <chrono>
#include <thread>
#endif

using namespace yuzu::agent::macos;

// ── mach_abs_to_100ns — pure, every host ─────────────────────────────────────

TEST_CASE("mach_abs_to_100ns converts ticks->100ns via the host timebase", "[dex][macos][perf]") {
    // Real Apple Silicon timebase (1 tick ~= 125/3 ns): 1000 ticks -> 41666 ns -> 416
    // (integer division at each step, matching the implementation's own order).
    CHECK(mach_abs_to_100ns(1000, 125, 3) == 416);
    // Trivial 1:1 timebase.
    CHECK(mach_abs_to_100ns(1000, 1, 1) == 10);
    CHECK(mach_abs_to_100ns(0, 125, 3) == 0);
}

TEST_CASE("mach_abs_to_100ns never divides by a zero denominator", "[dex][macos][perf]") {
    CHECK(mach_abs_to_100ns(1000, 125, 0) == 0);
}

TEST_CASE("mach_abs_to_100ns saturates rather than wraps on overflow", "[dex][macos][perf]") {
    constexpr auto kMax = std::numeric_limits<std::uint64_t>::max();
    // t*numer overflows 64 bits enormously; the saturating multiply pins the
    // intermediate ns value at kMax rather than wrapping, so the final result is
    // exactly kMax/1/100 — a wrap would instead produce something small/inconsistent.
    CHECK(mach_abs_to_100ns(kMax, 1000, 1) == kMax / 100);
}

// ── cpu_busy_pct — pure, every host ──────────────────────────────────────────

TEST_CASE("cpu_busy_pct derives busy% from a steady CpuTicks interval", "[dex][macos][perf]") {
    const CpuTicks prev{.valid = true, .user = 100, .system = 50, .nice = 10, .idle = 840};
    const CpuTicks cur{.valid = true, .user = 200, .system = 100, .nice = 10, .idle = 1690};
    // dt = 2000-1000 = 1000, di = 1690-840 = 850, busy = 100*(1000-850)/1000 = 15.
    const auto pct = cpu_busy_pct(prev, cur);
    REQUIRE(pct.has_value());
    CHECK(*pct == Catch::Approx(15.0));
}

TEST_CASE("cpu_busy_pct reads an idle-only interval as 0", "[dex][macos][perf]") {
    const CpuTicks prev{.valid = true, .user = 100, .system = 50, .nice = 10, .idle = 840};
    const CpuTicks cur{.valid = true, .user = 100, .system = 50, .nice = 10, .idle = 940};
    const auto pct = cpu_busy_pct(prev, cur);
    REQUIRE(pct.has_value());
    CHECK(*pct == Catch::Approx(0.0));
}

TEST_CASE("cpu_busy_pct rejects invalid input, a field regression, and zero elapsed time",
          "[dex][macos][perf]") {
    const CpuTicks base{.valid = true, .user = 100, .system = 50, .nice = 10, .idle = 840};
    CHECK_FALSE(cpu_busy_pct(CpuTicks{}, base).has_value());   // prev invalid
    CHECK_FALSE(cpu_busy_pct(base, CpuTicks{}).has_value());   // cur invalid
    CHECK_FALSE(cpu_busy_pct(base, base).has_value());         // zero elapsed

    // Every field is its own independently monotonic counter (unlike
    // yuzu::agent::lnx::CpuJiffies's single derived total) — each one regressing on
    // its own must reject, not just the field the original case happened to pick.
    CpuTicks r = base;
    r.user = base.user - 1;
    CHECK_FALSE(cpu_busy_pct(base, r).has_value()); // user regression
    r = base;
    r.system = base.system - 1;
    CHECK_FALSE(cpu_busy_pct(base, r).has_value()); // system regression
    r = base;
    r.nice = base.nice - 1;
    CHECK_FALSE(cpu_busy_pct(base, r).has_value()); // nice regression
    r = base;
    r.idle = base.idle - 1;
    CHECK_FALSE(cpu_busy_pct(base, r).has_value()); // idle regression
}

// ── disk_await_ms — pure, every host ─────────────────────────────────────────

TEST_CASE("disk_await_ms derives await-ms from a known before/after DiskTotals",
          "[dex][macos][perf]") {
    const DiskTotals prev{.valid = true,
                          .read_bytes = 0,
                          .write_bytes = 0,
                          .reads = 10,
                          .writes = 10,
                          .read_time_ns = 1'000'000,
                          .write_time_ns = 1'000'000};
    const DiskTotals cur{.valid = true,
                         .read_bytes = 0,
                         .write_bytes = 0,
                         .reads = 20,
                         .writes = 20,
                         .read_time_ns = 3'000'000,
                         .write_time_ns = 3'000'000};
    // dops = 20, dtime_ns = 4,000,000 -> 4ms / 20 ops = 0.2ms.
    const auto ms = disk_await_ms(prev, cur);
    REQUIRE(ms.has_value());
    CHECK(*ms == Catch::Approx(0.2));
}

TEST_CASE("disk_await_ms reads a zero-op interval as an idle 0.0, not slow", "[dex][macos][perf]") {
    const DiskTotals same{
        .valid = true, .reads = 5, .writes = 5, .read_time_ns = 10, .write_time_ns = 10};
    const auto ms = disk_await_ms(same, same);
    REQUIRE(ms.has_value());
    CHECK(*ms == Catch::Approx(0.0));
}

TEST_CASE("disk_await_ms rejects invalid input and a counter regression", "[dex][macos][perf]") {
    const DiskTotals base{
        .valid = true, .reads = 10, .writes = 10, .read_time_ns = 100, .write_time_ns = 100};
    CHECK_FALSE(disk_await_ms(DiskTotals{}, base).has_value());
    CHECK_FALSE(disk_await_ms(base, DiskTotals{}).has_value());

    // Every field disk_await_ms actually reads (reads/writes/read_time_ns/write_time_ns)
    // is checked for regression independently — each one regressing on its own must
    // reject, not just the field the original case happened to pick.
    DiskTotals r = base;
    r.reads = base.reads - 1;
    CHECK_FALSE(disk_await_ms(base, r).has_value()); // reads regression
    r = base;
    r.writes = base.writes - 1;
    CHECK_FALSE(disk_await_ms(base, r).has_value()); // writes regression
    r = base;
    r.read_time_ns = base.read_time_ns - 1;
    CHECK_FALSE(disk_await_ms(base, r).has_value()); // read_time_ns regression
    r = base;
    r.write_time_ns = base.write_time_ns - 1;
    CHECK_FALSE(disk_await_ms(base, r).has_value()); // write_time_ns regression
}

// ── memory_pressure_pct — pure, every host ───────────────────────────────────

TEST_CASE("memory_pressure_pct is the complement of kern.memorystatus_level, clamped",
          "[dex][macos][perf]") {
    CHECK(memory_pressure_pct(100) == Catch::Approx(0.0));
    CHECK(memory_pressure_pct(0) == Catch::Approx(100.0));
    // Out-of-range clamps stay DEFENCE IN DEPTH here (governance C-2): the production
    // path never reaches this function with an out-of-range level any more —
    // read_memorystatus_level() now returns nullopt outside [0,100] itself, before this
    // function ever sees the value — but a caller bypassing that reader must still get a
    // clamped, never a nonsensical negative/>100, result.
    CHECK(memory_pressure_pct(137) == Catch::Approx(0.0));  // out of range, clamped
    CHECK(memory_pressure_pct(-20) == Catch::Approx(100.0)); // out of range, clamped
}

// ── vm_used_bytes — pure, every host ─────────────────────────────────────────

TEST_CASE("vm_used_bytes reduces wire+app+compressor pages to bytes", "[dex][macos][perf]") {
    // app = internal(500) - purgeable(50) = 450; used_pages = 100+450+20 = 570;
    // bytes = 570 * 4096.
    CHECK(vm_used_bytes(100, 500, 50, 20, 4096) == 570ULL * 4096ULL);
}

TEST_CASE("vm_used_bytes floors the app term at 0 when purgeable exceeds internal",
          "[dex][macos][perf]") {
    // app would underflow (5-20) without the floor; used_pages = wire(10)+0+compressor(0) = 10.
    CHECK(vm_used_bytes(10, 5, 20, 0, 100) == 1000ULL);
}

TEST_CASE("vm_used_bytes saturates rather than wraps on overflow", "[dex][macos][perf]") {
    constexpr auto kMax = std::numeric_limits<std::uint64_t>::max();
    CHECK(vm_used_bytes(kMax, 100, 0, 100, 2) == kMax);
}

#if defined(__APPLE__)

namespace {

// A live darwin source can genuinely be unavailable on this runner (a sandbox policy
// denying the syscall/sysctl OID, a VM/CI host with nothing to read, etc.) — that IS the
// documented "invalid/nullopt on failure" contract every read_* function in
// dex_macos_perf.hpp carries, not a defect. A bare REQUIRE on .valid/.has_value() asserts
// a documented failure mode cannot occur, which is itself the bug (governance C0-001 +
// C-10: this pattern was at five live sites in this file). SKIP()s instead, naming
// `source`, so the value assertions below a call site still run whenever a value is
// genuinely present, and an honest unavailability never fails the suite.
void require_or_skip(bool available, const char* source) {
    if (!available)
        SKIP("live source unavailable on this runner: " << source);
}

} // namespace

// ── Darwin-only readers: pinned live against this box ────────────────────────

TEST_CASE("read_cpu_ticks reads two valid, monotonic snapshots", "[dex][macos][perf][darwin]") {
    const auto a = read_cpu_ticks();
    require_or_skip(a.valid, "read_cpu_ticks (initial read)");

    // host_statistics(HOST_CPU_LOAD_INFO) publishes in ~1s batches on this kernel, so a
    // single fixed 50ms sleep left dt==0 on most windows (measured 6/10 and 8/12 pass —
    // the flaky case this replaces). Poll up to ~3s for a real elapsed interval instead
    // of trusting one fixed-length sleep; never lengthen a single sleep to paper over it.
    CpuTicks b{};
    for (int i = 0; i < 30; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        b = read_cpu_ticks();
        require_or_skip(b.valid, "read_cpu_ticks (poll)");
        if (b.user + b.system + b.nice + b.idle > a.user + a.system + a.nice + a.idle)
            break;
    }

    CHECK(b.user >= a.user);
    CHECK(b.system >= a.system);
    CHECK(b.nice >= a.nice);
    CHECK(b.idle >= a.idle);
    // The loop above breaks on a strict total increase (or exhausts its 30 x 100ms
    // budget) — assert that outcome explicitly. Without this, a reader that is VALID but
    // FROZEN (every field >= a's, none of them ever actually advancing) still passes the
    // four per-field CHECKs above, and the only place that would notice is the
    // conditional busy% check below, which this test deliberately tolerates a nullopt
    // from — so a genuinely frozen reader would otherwise go undetected.
    CHECK(b.user + b.system + b.nice + b.idle > a.user + a.system + a.nice + a.idle);

    // Conditional rather than REQUIRE: even after polling, an unlucky window can still
    // land on dt==0 (cpu_busy_pct's own contract) — that is not itself a failure here.
    const auto pct = cpu_busy_pct(a, b);
    if (pct.has_value()) {
        CHECK(*pct >= 0.0);
        CHECK(*pct <= 100.0);
    }
}

TEST_CASE("read_vm_snapshot's total matches an independent hw.memsize read",
          "[dex][macos][perf][darwin]") {
    const auto vm = read_vm_snapshot();
    require_or_skip(vm.valid, "read_vm_snapshot");
    std::uint64_t memsize = 0;
    std::size_t len = sizeof(memsize);
    REQUIRE(::sysctlbyname("hw.memsize", &memsize, &len, nullptr, 0) == 0);
    CHECK(vm.total_bytes == memsize);
    CHECK(vm.used_bytes < vm.total_bytes);
}

TEST_CASE("read_disk_totals reads real IOBlockStorageDriver counters", "[dex][macos][perf][darwin]") {
    // Verify driver presence INDEPENDENTLY of read_disk_totals() itself, so SKIP() means
    // "genuinely nothing to read on this runner" rather than silently masking a real
    // read_disk_totals defect behind the same call this test is meant to pin. RAII-owned
    // via ScopedIOObject/ScopedCFRef (never a manual IOObjectRelease/CFRelease in new
    // code — the same idiom production code uses,
    // agents/plugins/disk_actions/src/disk_actions_macos.cpp). Sums each driver's own
    // "Operations (Read)" key directly rather than merely counting drivers (governance
    // C-9): a bare driver-presence guard could pass on a freshly-booted host with zero
    // completed reads, then fail the CHECK below for an unrelated reason — this way the
    // guard and the assertion test the SAME condition.
    io_iterator_t raw_it{};
    REQUIRE(IOServiceGetMatchingServices(kIOMainPortDefault,
                                         IOServiceMatching(kIOBlockStorageDriverClass),
                                         &raw_it) == KERN_SUCCESS);
    yuzu::agent::ScopedIOObject it{raw_it};
    std::int64_t independent_reads = 0;
    for (io_object_t raw_obj; (raw_obj = IOIteratorNext(it.get()));) {
        yuzu::agent::ScopedIOObject obj{raw_obj};
        yuzu::agent::ScopedCFRef<CFTypeRef> stats{IORegistryEntryCreateCFProperty(
            obj.get(), CFSTR(kIOBlockStorageDriverStatisticsKey), kCFAllocatorDefault, 0)};
        if (!stats || CFGetTypeID(stats.get()) != CFDictionaryGetTypeID())
            continue;
        auto num = static_cast<CFNumberRef>(
            CFDictionaryGetValue(static_cast<CFDictionaryRef>(stats.get()),
                                 CFSTR(kIOBlockStorageDriverStatisticsReadsKey)));
        std::int64_t reads = 0;
        if (num && CFGetTypeID(num) == CFNumberGetTypeID() &&
            CFNumberGetValue(num, kCFNumberSInt64Type, &reads) && reads > 0)
            independent_reads += reads;
    }
    if (independent_reads == 0) {
        SKIP("no IOBlockStorageDriver reported a completed read on this runner (VM/CI host)");
    }

    // REQUIRE, not require_or_skip (governance xp-5): by this point independent_reads > 0
    // has ALREADY proven something on this host really did read data — reusing the exact
    // same independent probe the C-9 fix added, not a second one. A require_or_skip here
    // would let a future is_physical_storage_driver regression that excludes every real
    // physical disk (the invariant this test exists to catch) SKIP green instead of
    // failing — a false green on exactly the failure this test was added for. Distinct
    // from read_cpu_ticks/read_vm_snapshot/read_memorystatus_level above, which have no
    // equivalent independent proof-of-availability and so correctly stay require_or_skip.
    const auto disk = read_disk_totals();
    REQUIRE(disk.valid);
    CHECK(disk.reads > 0);
}

TEST_CASE("sum_block_storage_stats's empty-iterator arm reports invalid",
          "[dex][macos][perf][darwin]") {
    // Deterministic seam (governance Gate 3 SHOULD finding): a bogus IOKit service class
    // matches nothing, independent of this box's real (non-empty) driver population, so
    // the "zero drivers matched -> valid stays false" arm is pinned regardless of runner.
    // REQUIRE the lookup itself succeeded (nullopt there is inconclusive, not a pin) —
    // only then does out->valid==false actually pin the arm this test names.
    const auto out = sum_block_storage_stats_empty_iterator_for_test();
    REQUIRE(out.has_value());
    CHECK_FALSE(out->valid);
}

TEST_CASE("read_driver_stats's kSkip/kCorrupt/kAccumulated arms via a CF-dictionary fixture",
          "[dex][macos][perf][darwin]") {
    // Governance C-3: no live driver on this box's IOKit registry has a malformed or
    // corrupt "Statistics" dict, so kSkip and kCorrupt are otherwise unreachable from a
    // test here. Drives the SAME read_driver_stats() the production walk uses via a real
    // CFDictionary built from these six values, so the key-reading/type-checking code is
    // genuinely exercised, not reimplemented.

    SECTION("all six keys present and non-negative -> kAccumulated") {
        const auto r = read_driver_stats_for_test(100, 200, 10, 20, 1'000, 2'000);
        CHECK_FALSE(r.skipped);
        CHECK_FALSE(r.corrupt);
        CHECK(r.accumulated.read_bytes == 100);
        CHECK(r.accumulated.write_bytes == 200);
        CHECK(r.accumulated.reads == 10);
        CHECK(r.accumulated.writes == 20);
        CHECK(r.accumulated.read_time_ns == 1'000);
        CHECK(r.accumulated.write_time_ns == 2'000);
    }

    SECTION("one key omitted -> kSkip, not fatal") {
        const auto r = read_driver_stats_for_test(100, 200, 10, 20, 1'000, std::nullopt);
        CHECK(r.skipped);
        CHECK_FALSE(r.corrupt);
    }

    SECTION("one negative value among six present keys -> kCorrupt") {
        const auto r = read_driver_stats_for_test(100, 200, 10, 20, 1'000, -1);
        CHECK_FALSE(r.skipped);
        CHECK(r.corrupt);
    }
}

TEST_CASE("read_memorystatus_level reads a value in [0,100]", "[dex][macos][perf][darwin]") {
    const auto level = read_memorystatus_level();
    require_or_skip(level.has_value(), "read_memorystatus_level");
    CHECK(*level >= 0);
    CHECK(*level <= 100);
}

#else // !defined(__APPLE__)

// The all-invalid-stub contract every read_* function carries off Darwin
// (net_quality_sampler.cpp / dex_linux_proc.cpp shape) — never a half-filled struct,
// never a fabricated value, on a platform with no kernel to read from at all.
TEST_CASE("every darwin reader stub reports invalid off Apple", "[dex][macos][perf]") {
    CHECK_FALSE(read_cpu_ticks().valid);
    CHECK_FALSE(read_vm_snapshot().valid);
    CHECK_FALSE(read_disk_totals().valid);
    CHECK_FALSE(read_memorystatus_level().has_value());
}

#endif // __APPLE__
