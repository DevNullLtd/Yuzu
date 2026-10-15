/**
 * test_tar_proc_perf.cpp — per-app top-N sampling for the TAR edge warehouse
 * (BRD A2).
 *
 * Two halves:
 *  1. derive_proc_samples (pure): the per-process cumulative-CPU → per-app
 *     share-of-capacity math — name aggregation, PID-reuse identity, new-
 *     process baselining, regression saturation, redaction, and the
 *     top-N-by-CPU ∪ top-N-by-working-set selection.
 *  2. Schema-registry pins: the procperf source's tables exist, translate,
 *     are operator-queryable, and roll up hourly per (hour, name).
 *
 * The NtQuerySystemInformation read is the impure shell, exercised on a live
 * box; the rest runs on every host.
 */

#include "tar_proc_perf.hpp"
#include "tar_schema_registry.hpp"

#include <yuzu/version_string.hpp>

#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <string>
#include <unordered_map>
#include <vector>

using namespace yuzu::tar;
using Catch::Approx;

namespace {

constexpr std::uint64_t kSec100ns = 10'000'000ULL; // 100 ns units per second

ProcCounter proc(std::uint32_t pid, std::int64_t created, std::uint64_t cpu,
                 std::uint64_t ws, std::string name) {
    ProcCounter p;
    p.pid = pid;
    p.create_time_100ns = created;
    p.cpu_100ns = cpu;
    p.ws_bytes = ws;
    p.name = std::move(name);
    return p;
}

// A 4-core snapshot pair 30 s apart; tests add processes to both.
ProcSnapshot snap(std::int64_t ts) {
    ProcSnapshot s;
    s.valid = true;
    s.ts_epoch = ts;
    s.ncores = 4;
    return s;
}

const std::vector<std::string> kNoRedaction{};

} // namespace

// ── derive_proc_samples ──────────────────────────────────────────────────────

TEST_CASE("procperf derive: invalid snapshots / zero elapsed / zero cores never derive",
          "[tar][procperf]") {
    auto prev = snap(1000), cur = snap(1030);
    prev.procs.push_back(proc(10, 1, 0, 100, "a.exe"));
    cur.procs.push_back(proc(10, 1, kSec100ns, 100, "a.exe"));

    ProcSnapshot invalid;
    CHECK(derive_proc_samples(invalid, cur, kNoRedaction).empty());
    CHECK(derive_proc_samples(prev, invalid, kNoRedaction).empty());
    CHECK(derive_proc_samples(cur, prev, kNoRedaction).empty()); // elapsed < 0
    auto nocores = cur;
    nocores.ncores = 0;
    CHECK(derive_proc_samples(prev, nocores, kNoRedaction).empty());
}

TEST_CASE("procperf derive: CPU is the app's share of TOTAL capacity", "[tar][procperf]") {
    // One process burns exactly one full core for 30 s on a 4-core box → 25%.
    auto prev = snap(1000), cur = snap(1030);
    prev.procs.push_back(proc(10, 1, 0, 50 << 20, "burner.exe"));
    cur.procs.push_back(proc(10, 1, 30 * kSec100ns, 50 << 20, "burner.exe"));
    const auto out = derive_proc_samples(prev, cur, kNoRedaction);
    REQUIRE(out.size() == 1);
    CHECK(out[0].name == "burner.exe");
    CHECK(out[0].cpu_pct == Approx(25.0));
    CHECK(out[0].ws_bytes == (50 << 20));
    CHECK(out[0].instances == 1);
}

TEST_CASE("procperf derive: same-name processes aggregate into one app row",
          "[tar][procperf]") {
    auto prev = snap(1000), cur = snap(1030);
    for (std::uint32_t pid : {11u, 12u, 13u}) {
        prev.procs.push_back(proc(pid, 1, 0, 100 << 20, "chrome.exe"));
        cur.procs.push_back(proc(pid, 1, 10 * kSec100ns, 100 << 20, "chrome.exe"));
    }
    const auto out = derive_proc_samples(prev, cur, kNoRedaction);
    REQUIRE(out.size() == 1);
    CHECK(out[0].instances == 3);
    CHECK(out[0].cpu_pct == Approx(25.0)); // 3 × 10 s of CPU over 120 core-seconds
    CHECK(out[0].ws_bytes == 3LL * (100 << 20));
}

TEST_CASE("procperf derive: is_kthread flows through to the aggregated sample",
          "[tar][procperf]") {
    auto prev = snap(1000), cur = snap(1030);
    // A kernel thread and a normal process, tracked independently by name.
    auto kt_prev = proc(2, 1, 0, 0, "kworker/0:1");
    auto kt_cur = proc(2, 1, kSec100ns, 0, "kworker/0:1");
    kt_prev.is_kthread = kt_cur.is_kthread = true;
    prev.procs.push_back(kt_prev);
    cur.procs.push_back(kt_cur);
    prev.procs.push_back(proc(10, 1, 0, 1 << 20, "normal.exe"));
    cur.procs.push_back(proc(10, 1, kSec100ns, 1 << 20, "normal.exe"));

    const auto out = derive_proc_samples(prev, cur, kNoRedaction);
    REQUIRE(out.size() == 2);
    for (const auto& s : out) {
        if (s.name == "kworker/0:1")
            CHECK(s.is_kthread == true);
        else if (s.name == "normal.exe")
            CHECK(s.is_kthread == false);
        else
            FAIL("unexpected sample name: " << s.name);
    }
}

TEST_CASE("procperf derive: is_kthread is OR'd across same-name instances",
          "[tar][procperf]") {
    // Same name, one instance flagged is_kthread and one not — the aggregate
    // must read true (the conservative/inclusive direction, matching the
    // comm-width redaction fallback's own "only ever ADDS" precedent).
    auto prev = snap(1000), cur = snap(1030);
    auto a_prev = proc(11, 1, 0, 0, "shared-name");
    auto a_cur = proc(11, 1, kSec100ns, 0, "shared-name");
    a_prev.is_kthread = a_cur.is_kthread = true;
    auto b_prev = proc(12, 1, 0, 0, "shared-name");
    auto b_cur = proc(12, 1, kSec100ns, 0, "shared-name");
    prev.procs.push_back(a_prev);
    cur.procs.push_back(a_cur);
    prev.procs.push_back(b_prev);
    cur.procs.push_back(b_cur);

    const auto out = derive_proc_samples(prev, cur, kNoRedaction);
    REQUIRE(out.size() == 1);
    CHECK(out[0].instances == 2);
    CHECK(out[0].is_kthread == true);
}

TEST_CASE("procperf derive: PID reuse (different create_time) finds no baseline",
          "[tar][procperf]") {
    // Same PID, different create_time = a DIFFERENT process. Its inherited
    // cumulative CPU must not read as this interval's burn.
    auto prev = snap(1000), cur = snap(1030);
    prev.procs.push_back(proc(10, /*created=*/111, 5 * kSec100ns, 10 << 20, "old.exe"));
    cur.procs.push_back(proc(10, /*created=*/999, 20 * kSec100ns, 10 << 20, "new.exe"));
    const auto out = derive_proc_samples(prev, cur, kNoRedaction);
    REQUIRE(out.size() == 1);
    CHECK(out[0].name == "new.exe");
    CHECK(out[0].cpu_pct == 0.0);          // baselines this interval
    CHECK(out[0].ws_bytes == (10 << 20)); // working set still real
}

TEST_CASE("procperf derive: CPU counter regression saturates to zero", "[tar][procperf]") {
    auto prev = snap(1000), cur = snap(1030);
    prev.procs.push_back(proc(10, 1, 50 * kSec100ns, 1 << 20, "a.exe"));
    cur.procs.push_back(proc(10, 1, 40 * kSec100ns, 1 << 20, "a.exe")); // impossible: went down
    const auto out = derive_proc_samples(prev, cur, kNoRedaction);
    REQUIRE(out.size() == 1);
    CHECK(out[0].cpu_pct == 0.0);
}

TEST_CASE("procperf derive: redacted and empty names never appear", "[tar][procperf]") {
    auto prev = snap(1000), cur = snap(1030);
    prev.procs.push_back(proc(10, 1, 0, 1 << 20, "secret-tool.exe"));
    cur.procs.push_back(proc(10, 1, kSec100ns, 1 << 20, "secret-tool.exe"));
    prev.procs.push_back(proc(11, 1, 0, 1 << 20, "normal.exe"));
    cur.procs.push_back(proc(11, 1, kSec100ns, 1 << 20, "normal.exe"));
    cur.procs.push_back(proc(12, 1, 0, 1 << 20, "")); // unnameable kernel entry

    const std::vector<std::string> redaction{"secret*"};
    const auto out = derive_proc_samples(prev, cur, redaction);
    REQUIRE(out.size() == 1);
    CHECK(out[0].name == "normal.exe");
}

TEST_CASE("procperf derive: top-N union keeps the CPU-idle memory hog visible",
          "[tar][procperf]") {
    auto prev = snap(1000), cur = snap(1030);
    // 12 CPU-busy small apps (descending burn so the top-10 cut is decided)…
    for (std::uint32_t i = 0; i < 12; ++i) {
        const auto cpu = static_cast<std::uint64_t>(12 - i) * kSec100ns;
        prev.procs.push_back(proc(100 + i, 1, 0, 1 << 20, "busy" + std::to_string(i) + ".exe"));
        cur.procs.push_back(
            proc(100 + i, 1, cpu, 1 << 20, "busy" + std::to_string(i) + ".exe"));
    }
    // …and one CPU-idle app holding 8 GiB.
    prev.procs.push_back(proc(200, 1, 0, 8ULL << 30, "hog.exe"));
    cur.procs.push_back(proc(200, 1, 0, 8ULL << 30, "hog.exe"));

    const auto out = derive_proc_samples(prev, cur, kNoRedaction);
    // 13 apps: top-10 by CPU (busy0..busy9) ∪ top-10 by WS (hog + 9 others).
    CHECK(out.size() <= 2 * static_cast<std::size_t>(kProcTopN));
    const bool hog_present = std::any_of(out.begin(), out.end(), [](const ProcPerfSample& s) {
        return s.name == "hog.exe";
    });
    CHECK(hog_present);
    // Presentation order: CPU-heaviest first.
    REQUIRE(out.size() >= 2);
    CHECK(out[0].cpu_pct >= out[1].cpu_pct);
    // The least CPU-busy app (busy11) made neither top list… unless the WS
    // tie pulled it in — assert only the structural bound + hog presence.
}

TEST_CASE("procperf derive: an absurd delta clamps at 100%", "[tar][procperf]") {
    auto prev = snap(1000), cur = snap(1030);
    // 10x more CPU time than the interval has capacity (forged/garbage).
    prev.procs.push_back(proc(10, 1, 0, 1 << 20, "liar.exe"));
    cur.procs.push_back(proc(10, 1, 30 * 4 * 10 * kSec100ns, 1 << 20, "liar.exe"));
    const auto out = derive_proc_samples(prev, cur, kNoRedaction);
    REQUIRE(out.size() == 1);
    CHECK(out[0].cpu_pct == 100.0);
}

TEST_CASE("procperf derive: the representative is the largest-working-set instance",
          "[tar][procperf]") {
    // version resolution (off-lock, Windows) targets ONE instance per app — the
    // biggest-WS one. derive must surface that pid + its create_time as rep_*,
    // and leave version "" (the resolver fills it later).
    auto prev = snap(1000), cur = snap(1030);
    struct Inst { std::uint32_t pid; std::int64_t ct; std::uint64_t ws; };
    const Inst insts[] = {{11, 4001, 100u << 20}, {12, 4002, 300u << 20}, {13, 4003, 200u << 20}};
    for (const auto& i : insts) {
        prev.procs.push_back(proc(i.pid, i.ct, 0, i.ws, "chrome.exe"));
        cur.procs.push_back(proc(i.pid, i.ct, kSec100ns, i.ws, "chrome.exe"));
    }
    const auto out = derive_proc_samples(prev, cur, kNoRedaction);
    REQUIRE(out.size() == 1);
    CHECK(out[0].instances == 3);
    CHECK(out[0].rep_pid == 12);                 // the 300 MiB instance
    CHECK(out[0].rep_create_time_100ns == 4002); // its identity, for the PID-reuse guard
    CHECK(out[0].version.empty());               // unresolved until resolve_proc_versions
}

// ── shared version normalization (pure, cross-platform) ──────────────────────

TEST_CASE("version_string: VS_FIXEDFILEINFO words format as a.b.c.d", "[tar][procperf][version]") {
    using yuzu::util::format_file_version;
    // ms = HIWORD.LOWORD, ls = HIWORD.LOWORD — e.g. Chrome 124.0.6367.91.
    CHECK(format_file_version(0x007C0000u, 0x18DF005Bu) == "124.0.6367.91");
    CHECK(format_file_version(0u, 0u) == "0.0.0.0");
    CHECK(format_file_version(0xFFFFFFFFu, 0xFFFFFFFFu) == "65535.65535.65535.65535");
    CHECK(format_file_version(0x000A0001u, 0x00000000u) == "10.1.0.0");
}

TEST_CASE("version_string: normalize_ffi_version maps the all-zero fixed version to ''",
          "[tar][procperf][version]") {
    using yuzu::util::normalize_ffi_version;
    // The contract the perf-side resolver relies on but never exercised in CI
    // (the all-zero guard lived inline in the Windows-only impure shell, quality-1).
    CHECK(normalize_ffi_version(0u, 0u).empty());          // "no real version" -> unknown bucket
    CHECK(normalize_ffi_version(0x007C0000u, 0x18DF005Bu) == "124.0.6367.91");
    CHECK(normalize_ffi_version(0x000A0001u, 0u) == "10.1.0.0");
}

TEST_CASE("version_string: canon_version normalizes to exactly 4 groups, joins perf",
          "[tar][procperf][version]") {
    using yuzu::util::canon_version;
    using yuzu::util::format_file_version;
    // Already a 4-group quad -> unchanged (the dominant WER case).
    CHECK(canon_version("6.15.101.7085") == "6.15.101.7085");
    // ARITY FIX (UP-2): short forms pad to 4 so they byte-match format_file_version,
    // which is ALWAYS 4 groups. Before this, "3.2" stayed "3.2" and never joined
    // the perf row "3.2.0.0".
    CHECK(canon_version("3.2") == "3.2.0.0");
    CHECK(canon_version("3.2") == format_file_version(0x00030002u, 0u)); // proves the join
    CHECK(canon_version("10") == "10.0.0.0");
    // Trailing non-numeric suffix dropped (live-observed explorer.exe form).
    CHECK(canon_version("10.0.26100.8457 (WinBuild.160101.0800)") == "10.0.26100.8457");
    // Leading zeros normalized through the integer parse (matches format_file_version).
    CHECK(canon_version("01.02.03.04") == "1.2.3.4");
    // > 4 groups capped at 4.
    CHECK(canon_version("1.2.3.4.5.6") == "1.2.3.4");
    // all-zero and empty and non-numeric all collapse to the unknown bucket.
    CHECK(canon_version("0.0.0.0").empty());
    CHECK(canon_version("").empty());
    CHECK(canon_version("not.a.version").empty());
    // UP-12 length guard: an absurd digit run is rejected, not echoed unbounded.
    CHECK(canon_version(std::string(10000, '9')).empty());
}

TEST_CASE("procperf version: resolve_proc_versions is a no-op when there is no representative",
          "[tar][procperf]") {
    // A sample with rep_pid==0 (no instance recorded) is left version="" and the
    // cache untouched — and off Windows the whole call is a no-op, so this holds
    // on every host.
    std::vector<ProcPerfSample> samples(1);
    samples[0].name = "ghost.exe";
    std::unordered_map<std::uint64_t, std::string> cache;
    resolve_proc_versions(samples, cache);
    CHECK(samples[0].version.empty());
}

// ── Schema-registry pins ─────────────────────────────────────────────────────

TEST_CASE("procperf: registry declares both tiers, dollar names translate",
          "[tar][procperf][schema]") {
    auto live = translate_dollar_name("$ProcPerf_Live");
    REQUIRE(live.has_value());
    CHECK(*live == "procperf_live");
    auto hourly = translate_dollar_name("$ProcPerf_Hourly");
    REQUIRE(hourly.has_value());
    CHECK(*hourly == "procperf_hourly");
    CHECK(is_queryable_table("procperf_live"));
    CHECK(is_queryable_table("procperf_hourly"));
}

TEST_CASE("procperf: hourly rollup SQL exists and groups per (hour, name, version)",
          "[tar][procperf][schema]") {
    const auto sql = rollup_sql("procperf", "hourly");
    REQUIRE(!sql.empty());
    CHECK(sql.find("procperf_hourly") != std::string::npos);
    // version is part of the app identity — it must appear in BOTH the column
    // list and the GROUP BY, or the hourly tier would collapse distinct
    // versions of one app into a single (mislabelled) row.
    CHECK(sql.find("GROUP BY (ts / 3600) * 3600, name, version") != std::string::npos);
    CHECK(sql.find("(hour_ts, name, version,") != std::string::npos);
    CHECK(sql.find("MAX(instances)") != std::string::npos);
    // is_kthread rides the GROUP BY as an identity column (never aggregated)
    // so a kernel-thread and non-kernel-thread row sharing a (name, version)
    // never collapse into one mislabelled row.
    CHECK(sql.find("is_kthread") != std::string::npos);
    CHECK(sql.find("GROUP BY (ts / 3600) * 3600, name, version, is_kthread") != std::string::npos);
}

TEST_CASE("procperf: live columns carry name but never a cmdline", "[tar][procperf][schema]") {
    // Privacy pin: the A2 tier records image NAMES only. A cmdline column
    // appearing here is a design regression, not an addition.
    const auto ddl = generate_warehouse_ddl();
    const auto pos = ddl.find("CREATE TABLE IF NOT EXISTS procperf_live");
    REQUIRE(pos != std::string::npos);
    const auto end = ddl.find(");", pos);
    const auto table_ddl = ddl.substr(pos, end - pos);
    CHECK(table_ddl.find("name TEXT") != std::string::npos);
    CHECK(table_ddl.find("version TEXT") != std::string::npos); // the app-identity dimension
    CHECK(table_ddl.find("is_kthread INTEGER") != std::string::npos); // kernel-thread marker
    CHECK(table_ddl.find("cmdline") == std::string::npos);
    CHECK(table_ddl.find("user") == std::string::npos);
    CHECK(table_ddl.find("path") == std::string::npos); // never the image PATH (privacy)
}

TEST_CASE("procperf #538: a reset baseline (post-disable) emits no off-period-spanning row",
          "[tar][procperf][source-lifecycle]") {
    // do_collect_perf's procperf disable branch installs a default-constructed
    // ProcSnapshot as prev_proc_ (valid=false). On the first tick after a
    // re-enable, deriving against that reset baseline must yield NO samples (it
    // re-baselines) even though the app accrued CPU during the paused window — so
    // the first post-re-enable row never covers the opt-out window. Without the
    // reset, prev_proc_ would still hold the pre-disable snapshot and this call
    // would emit a per-app row spanning the gap (the privacy leak on the opt-in
    // source procperf, off by default for exactly this reason).
    auto after_gap = snap(100'000);                                 // long pause elapsed
    after_gap.procs.push_back(proc(10, 1, 900 * kSec100ns, 100, "a.exe")); // lots of CPU

    // The disable branch's reset == a default-constructed prev → no rows.
    CHECK(derive_proc_samples(ProcSnapshot{}, after_gap, kNoRedaction).empty());
    // Sanity: against a real pre-gap baseline it WOULD emit a row — the
    // off-period leak the reset prevents.
    auto prev = snap(1000);
    prev.procs.push_back(proc(10, 1, 0, 100, "a.exe"));
    CHECK_FALSE(derive_proc_samples(prev, after_gap, kNoRedaction).empty());
}

// ── parse_linux_pid_stat (pure — runs on every host) ─────────────────────────

TEST_CASE("procperf: Linux pid-stat parse — field indices and unit conversions",
          "[tar][procperf][linux]") {
    // A realistic line, hand-annotated: utime=1500 stime=1500 (fields 14/15),
    // starttime=5000 (field 22), rss=2048 pages (field 24). Any off-by-one in
    // the post-comm token walk breaks these exact expectations.
    const auto p = parse_linux_pid_stat(
        1234,
        "1234 (nginx) S 1 1234 1234 0 -1 4194560 2500 0 0 0 1500 1500 0 0 20 0 1 0 "
        "5000 12345678 2048 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 0 0 0",
        100, 4096);
    REQUIRE(p);
    CHECK(p->pid == 1234);
    CHECK(p->name == "nginx");
    CHECK(p->cpu_100ns == 3000ULL * 100'000);            // ticks ×1e7/clk_tck @ 100 Hz
    CHECK(p->create_time_100ns == 5000LL * 100'000);     // boot-relative, identity-only
    CHECK(p->ws_bytes == 2048ULL * 4096);                // rss pages × page size
    // flags=4194560 (0x400100) — PF_KTHREAD (0x00200000) is NOT set; a normal
    // user-space process (nginx) must never read as a kernel thread.
    CHECK(p->is_kthread == false);

    SECTION("clk_tck scaling") {
        const char* line = "1 (a) S 0 0 0 0 0 0 0 0 0 0 1500 1500 0 0 20 0 1 0 5000 0 10 0";
        const auto p250 = parse_linux_pid_stat(1, line, 250, 4096);
        REQUIRE(p250);
        CHECK(p250->cpu_100ns == 3000ULL * 40'000);
        const auto p1000 = parse_linux_pid_stat(1, line, 1000, 4096);
        REQUIRE(p1000);
        CHECK(p1000->cpu_100ns == 3000ULL * 10'000);
    }
    SECTION("page-size scaling") {
        const char* line = "1 (a) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 20 0 1 0 1 0 10 0";
        const auto pp = parse_linux_pid_stat(1, line, 100, 16384);
        REQUIRE(pp);
        CHECK(pp->ws_bytes == 10ULL * 16384);
    }
    SECTION("negative rss clamps to 0; negative starttime rejects the row") {
        const auto neg_rss = parse_linux_pid_stat(
            1, "1 (a) S 0 0 0 0 0 0 0 0 0 0 5 5 0 0 20 0 1 0 5000 0 -1 0", 100, 4096);
        REQUIRE(neg_rss);
        CHECK(neg_rss->ws_bytes == 0);
        // starttime parses as uint64 — "-1" fails full consumption → nullopt.
        CHECK(!parse_linux_pid_stat(
            1, "1 (a) S 0 0 0 0 0 0 0 0 0 0 5 5 0 0 20 0 1 0 -1 0 10 0", 100, 4096));
    }
    SECTION("empty comm \"()\" parses with an empty name — derive drops it, never a row") {
        const auto p = parse_linux_pid_stat(
            1, "1 () S 0 0 0 0 0 0 0 0 0 0 5 5 0 0 20 0 1 0 5000 0 10 0", 100, 4096);
        REQUIRE(p);
        CHECK(p->name.empty());
    }
    SECTION("reversed parens \")(\" is malformed — close before open rejects") {
        CHECK(!parse_linux_pid_stat(1, "1 )( S 0 0 0 0 0", 100, 4096));
    }
}

TEST_CASE("procperf: Linux pid-stat parse — comm adversaries and malformed input",
          "[tar][procperf][linux]") {
    const char* tail = " R 1 2 2 0 -1 0 0 0 0 0 700 300 0 0 20 0 1 0 900 0 512 0";
    SECTION("comm with spaces (tmux: server)") {
        const auto p = parse_linux_pid_stat(55, std::string("55 (tmux: server)") + tail, 100, 4096);
        REQUIRE(p);
        CHECK(p->name == "tmux: server");
        CHECK(p->cpu_100ns == 1000ULL * 100'000); // utime 700 + stime 300
    }
    SECTION("comm with embedded parens — last-')' rule") {
        const auto p = parse_linux_pid_stat(77, std::string("77 (a) b (c))") + tail, 100, 4096);
        REQUIRE(p);
        CHECK(p->name == "a) b (c)");
    }
    SECTION("kernel-thread line parses with rss 0") {
        const auto p = parse_linux_pid_stat(
            2, "2 (kthreadd) S 0 0 0 0 -1 2129984 0 0 0 0 12 34 0 0 20 0 1 0 25 0 0 0", 100,
            4096);
        REQUIRE(p);
        CHECK(p->name == "kthreadd");
        CHECK(p->ws_bytes == 0); // self-excludes from the working-set top-N
        // flags=2129984 (0x208040) — PF_KTHREAD (0x00200000) IS set: a real
        // captured kthreadd flags word, not a synthetic fixture.
        CHECK(p->is_kthread == true);
    }
    SECTION("malformed content is nullopt, never a throw") {
        CHECK(!parse_linux_pid_stat(1, "", 100, 4096));
        CHECK(!parse_linux_pid_stat(1, "1234 (x S 1 2 3", 100, 4096));   // no closing paren
        CHECK(!parse_linux_pid_stat(1, "1234 (x) S 1 2 3", 100, 4096)); // too few fields
        CHECK(!parse_linux_pid_stat(1, "1234 (x) S a b c d e f g h i j k l m n o p q r s t u v",
                                    100, 4096)); // non-numeric fields
    }
    SECTION("non-positive clk_tck / page_size is nullopt") {
        const std::string line = std::string("1 (a)") + tail;
        CHECK(!parse_linux_pid_stat(1, line, 0, 4096));
        CHECK(!parse_linux_pid_stat(1, line, 100, 0));
    }
}

TEST_CASE("procperf: is_kthread is PF_KTHREAD-flag-derived, not comm-derived",
          "[tar][procperf][linux]") {
    // A process can trivially name itself "kworker/0:1" via prctl(PR_SET_NAME)
    // (tar_proc_perf.hpp's "Kernel-thread marker" note) — the flag bit, never
    // the name, is what parse_linux_pid_stat consults.
    auto stat_line = [](std::uint32_t pid, std::string_view comm, std::uint64_t flags) {
        return std::to_string(pid) + " (" + std::string(comm) + ") S 0 0 0 0 -1 " +
               std::to_string(flags) + " 0 0 0 0 5 5 0 0 20 0 1 0 25 0 0 0";
    };
    SECTION("exact PF_KTHREAD bit (0x00200000) set, comm looks like a real app") {
        const auto p = parse_linux_pid_stat(5, stat_line(5, "totally-legit.exe", 0x00200000),
                                            100, 4096);
        REQUIRE(p);
        CHECK(p->name == "totally-legit.exe");
        CHECK(p->is_kthread == true); // 0x00200000 exactly
    }
    SECTION("adjacent bits set, PF_KTHREAD itself clear, comm looks like a kernel thread") {
        // 0x00100000 (PF_KSWAPD, an adjacent-but-different flag) — spoofing the
        // NAME to "kworker/0:1" must not fool the flag check either.
        const auto p = parse_linux_pid_stat(6, stat_line(6, "kworker/0:1", 0x00100000), 100, 4096);
        REQUIRE(p);
        CHECK(p->name == "kworker/0:1");
        CHECK(p->is_kthread == false);
    }
    SECTION("flags=0 is never a kernel thread") {
        const auto p = parse_linux_pid_stat(7, stat_line(7, "a", 0), 100, 4096);
        REQUIRE(p);
        CHECK(p->is_kthread == false);
    }
    SECTION("unparseable flags field rejects the row (same discipline as utime/rss)") {
        CHECK(!parse_linux_pid_stat(
            8, "8 (a) S 0 0 0 0 -1 notanumber 0 0 0 0 5 5 0 0 20 0 1 0 25 0 0 0", 100, 4096));
    }
}

TEST_CASE("procperf: Linux comm is sanitized for the wire, escaped for the name join",
          "[tar][procperf][linux]") {
    const char* tail = " R 1 2 2 0 -1 0 0 0 0 0 700 300 0 0 20 0 1 0 900 0 512 0";
    // comm is attacker-settable raw bytes (prctl(PR_SET_NAME)). '|' would
    // inject separators into the pipe-delimited sql/export/app_perf formats;
    // '\' and '\n' must match the kernel's /proc status Name: escaping (what
    // the process source records) so the name join holds.
    SECTION("pipe, control bytes, and DEL become '_'") {
        const auto p = parse_linux_pid_stat(9, std::string("9 (ev|l\tna\177me)") + tail, 100, 4096);
        REQUIRE(p);
        CHECK(p->name == "ev_l_na_me");
    }
    SECTION("backslash doubles, newline becomes literal \\n — status Name: parity") {
        const auto p =
            parse_linux_pid_stat(9, std::string("9 (dom\\svc\nx)") + tail, 100, 4096);
        REQUIRE(p);
        CHECK(p->name == "dom\\\\svc\\nx");
    }
    SECTION("valid multi-byte UTF-8 survives; ill-formed bytes become '_'") {
        // A legitimate non-ASCII name must round-trip; a lone lead byte, a
        // stray continuation, or a sequence truncated by the 15-byte comm cap
        // must be scrubbed so the stored name is always valid UTF-8 (else the
        // server's app_perf Postgres text insert would reject that device's row).
        const auto ok = parse_linux_pid_stat(9, std::string("9 (caf\xC3\xA9)") + tail, 100, 4096);
        REQUIRE(ok);
        CHECK(ok->name == "caf\xC3\xA9"); // é (U+00E9) preserved intact
        const auto bad = parse_linux_pid_stat(9, std::string("9 (a\xC3z\x80)") + tail, 100, 4096);
        REQUIRE(bad);
        CHECK(bad->name == "a_z_"); // truncated lead + stray continuation → '_'
        const auto overlong =
            parse_linux_pid_stat(9, std::string("9 (\xC0\xAF)") + tail, 100, 4096);
        REQUIRE(overlong);
        CHECK(overlong->name == "__"); // overlong '/' encoding rejected
    }
    SECTION("CR in the post-comm fields is whitespace, not a token byte") {
        // A CRLF-shaped stat line must parse identically to LF (the tokenizer's
        // whitespace set includes '\r', matching tar_perf's split_ws).
        const auto p = parse_linux_pid_stat(
            9, "9 (proc)\r\nR 1 2 2 0 -1 0 0 0 0 0 700 300 0 0 20 0 1 0 900 0 512 0\r\n", 100,
            4096);
        REQUIRE(p);
        CHECK(p->name == "proc");
        CHECK(p->cpu_100ns == 1000ULL * 100'000); // utime 700 + stime 300, unaffected by CR
    }
    SECTION("hostile huge fields saturate instead of wrapping to a small value") {
        // A forged /proc mount could put 2^64-scale integers in a field; the
        // saturating products must pin at the max, never wrap. (rss is parsed
        // as int64, so INT64_MAX is its hostile bound.)
        const auto p = parse_linux_pid_stat(
            1,
            "1 (x) R 0 0 0 0 0 0 0 0 0 0 18446744073709551615 0 0 0 20 0 1 0 0 0 "
            "9223372036854775807",
            100, 4096);
        REQUIRE(p);
        CHECK(p->cpu_100ns == std::numeric_limits<std::uint64_t>::max() / 100);
        CHECK(p->ws_bytes == std::numeric_limits<std::uint64_t>::max());
    }
}

TEST_CASE("procperf derive: comm-width redaction fallback catches long pattern cores",
          "[tar][procperf][linux]") {
    // A works-council operator redacts a full app name (> 15 chars). On Linux
    // the recorded name is the kernel's 15-byte comm — the full core can never
    // substring-match it, so the fallback must match the core's 15-byte
    // prefix instead. (kLinuxCommWidth pins the width.)
    auto prev = snap(1000), cur = snap(1030);
    prev.procs.push_back(proc(10, 1, 0, 100, "confidential-pl")); // 15-char comm
    cur.procs.push_back(proc(10, 1, kSec100ns, 100, "confidential-pl"));
    prev.procs.push_back(proc(11, 1, 0, 100, "innocent"));
    cur.procs.push_back(proc(11, 1, kSec100ns, 100, "innocent"));

    const std::vector<std::string> redaction{"*confidential-planning-tool*"};
    const auto rows = derive_proc_samples(prev, cur, redaction);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].name == "innocent"); // the redacted app never surfaces

    // Control: a short core (<= comm width) gets NO fallback — "outlook.exe"
    // deliberately does not match comm "outlook" (a Windows-specific pattern
    // on a Linux fleet is the operator's to fix; documented in tar.md).
    const std::vector<std::string> win_pattern{"outlook.exe"};
    auto p2 = snap(1000), c2 = snap(1030);
    p2.procs.push_back(proc(12, 1, 0, 100, "outlook"));
    c2.procs.push_back(proc(12, 1, kSec100ns, 100, "outlook"));
    CHECK(derive_proc_samples(p2, c2, win_pattern).size() == 1);
}

TEST_CASE("procperf derive: redaction matches in the SANITIZED comm space (mismatch fix)",
          "[tar][procperf][linux]") {
    // A process names itself with a wire-hostile byte (prctl). parse stores the
    // sanitized form (evil|app -> evil_app). An operator pattern written against
    // the RAW name (*evil|app*) must STILL redact it — the pattern is run through
    // the identical sanitization before matching, closing the mismatch a
    // raw-pattern match would leave (the app would otherwise leak into
    // procperf_live and the off-device app_perf sync).
    const char* tail = " R 1 2 2 0 -1 0 0 0 0 0 100 100 0 0 20 0 1 0 900 0 512 0";
    const auto pcur = parse_linux_pid_stat(20, std::string("20 (evil|app)") + tail, 100, 4096);
    const auto pprev = parse_linux_pid_stat(20, std::string("20 (evil|app)") + tail, 100, 4096);
    REQUIRE(pcur);
    REQUIRE(pcur->name == "evil_app"); // stored sanitized
    auto prev = snap(1000), cur = snap(1030);
    prev.procs.push_back(*pprev);
    cur.procs.push_back(*pcur);
    prev.procs.push_back(proc(21, 1, 0, 100, "innocent"));
    cur.procs.push_back(proc(21, 1, kSec100ns, 100, "innocent"));

    const std::vector<std::string> redaction{"*evil|app*"};
    const auto rows = derive_proc_samples(prev, cur, redaction);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].name == "innocent"); // evil_app was redacted despite the '|' mangle
}

TEST_CASE("procperf: Linux round-trip — parsed lines through derive_proc_samples",
          "[tar][procperf][linux]") {
    // 3000 ticks @ 100 Hz = 30 s of CPU over a 30 s interval on 4 cores → 25%
    // of total capacity (the tick→100 ns conversion feeds the unchanged
    // capacity denominator, elapsed·1e7·ncores).
    const char* pre = "42 (burner) R 1 42 42 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 77 0 1000 0";
    const char* post = "42 (burner) R 1 42 42 0 -1 0 0 0 0 0 1500 1500 0 0 20 0 1 0 77 0 1000 0";
    const auto a = parse_linux_pid_stat(42, pre, 100, 4096);
    const auto b = parse_linux_pid_stat(42, post, 100, 4096);
    REQUIRE(a);
    REQUIRE(b);

    auto prev = snap(1000), cur = snap(1030); // 4-core fixture snapshots
    prev.procs.push_back(*a);
    cur.procs.push_back(*b);
    const auto rows = derive_proc_samples(prev, cur, kNoRedaction);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].name == "burner");
    CHECK(rows[0].instances == 1);
    CHECK(rows[0].cpu_pct == Approx(25.0));
    CHECK(rows[0].ws_bytes == 1000LL * 4096);
    CHECK(rows[0].version.empty()); // Linux never resolves a version
}

#if defined(__linux__)
#include <unistd.h> // getpid

// Live-box smoke for the Linux impure shell — the /proc walk analogue of the
// Windows [live] version test below (in the default suite: it needs only the
// host's own /proc, no privileged reads).
TEST_CASE("procperf: LIVE Linux /proc snapshot smoke", "[tar][procperf][linux]") {
    const auto snapshot = read_proc_counters();
    REQUIRE(snapshot.valid);
    CHECK(snapshot.ncores > 0);
    const auto self = static_cast<std::uint32_t>(::getpid());
    bool found_self = false;
    for (const auto& p : snapshot.procs)
        if (p.pid == self) {
            found_self = true;
            CHECK(!p.name.empty());
            CHECK(p.ws_bytes > 0); // a running test binary has resident pages
        }
    CHECK(found_self);
}
#endif

#if defined(_WIN32)
// HIDDEN ([.]) — a manual, live-box smoke for the impure version-capture path
// (OpenProcess → GetProcessTimes guard → QueryFullProcessImageNameW →
// GetFileVersionInfo). It depends on the host's live process set and so is NOT
// in the default suite; run explicitly with the [live] tag. Builds samples
// straight off one snapshot (the rep is each process itself) to exercise
// resolve_proc_versions without the two-snapshot CPU timing.
TEST_CASE("procperf version: LIVE capture resolves real versions", "[.][procperf][live]") {
    const auto snapshot = read_proc_counters();
    REQUIRE(snapshot.valid);
    REQUIRE(!snapshot.procs.empty());

    std::vector<ProcPerfSample> samples;
    for (const auto& p : snapshot.procs) {
        if (p.name.empty())
            continue;
        ProcPerfSample s;
        s.name = p.name;
        s.rep_pid = p.pid;
        s.rep_create_time_100ns = p.create_time_100ns;
        samples.push_back(std::move(s));
        if (samples.size() >= 80)
            break;
    }
    std::unordered_map<std::uint64_t, std::string> cache;
    resolve_proc_versions(samples, cache);

    int resolved = 0;
    for (const auto& s : samples) {
        if (!s.version.empty()) {
            ++resolved;
            WARN(s.name << " -> " << s.version); // visible run output: the data point
        }
    }
    // Any real Windows host runs versioned system/vendor images (explorer.exe,
    // svchost.exe, the test exe). At least one must resolve to a.b.c.d — proof
    // the OpenProcess + file-version path works end-to-end, not just in theory.
    CHECK(resolved > 0);
}
#endif
