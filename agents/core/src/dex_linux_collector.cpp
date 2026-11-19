/**
 * dex_linux_collector.cpp — Linux server DEX collector (Guardian DEX).
 *
 * Linux servers have no event-driven OS signal bus the way Windows does
 * (EvtSubscribe), so the whole Linux DEX observer is a slow-cadence poll loop —
 * the dex_win_poll WinStatePoller shape, except it IS the ISignalObserver (there
 * is no event engine for it to ride alongside). v1 (PR3, the tracer-bullet slice)
 * reads /proc + statvfs and REUSES the existing cross-platform breach + poll-latch
 * + observation builders, so a Linux server lights up the same
 * perf.cpu_sustained / perf.memory_pressure / storage.low buckets as Windows and
 * macOS with ZERO server change (the macOS-collector parity playbook). journald
 * reliability signals (unit-failure, coredump crashes, OOM-kills) ride the same
 * poll loop via dex_linux_journal; os.uptime is a later slice.
 *
 * The pure /proc parsing lives in dex_linux_proc.{hpp,cpp} (tested off-Linux); the
 * statvfs read + the poll thread are the only Linux-only mechanism and live here
 * behind #if defined(__linux__) — an empty TU elsewhere, the dex_macos_collector
 * pattern. proto-free by design (the dex_observer.hpp rationale).
 */

#include <yuzu/agent/dex_observer.hpp>

#if defined(__linux__)

#include "dex_linux_journal.hpp" // parse_journal_line, kMsgId* (journald → DEX)
#include "dex_linux_proc.hpp"
#include "dex_linux_storage.hpp"  // storage_low_observation — the non-PII subject chokepoint
#include "dex_linux_sysfs.hpp"    // parse_throttle_count — /sys thermal-throttle counter
#include "dex_macos_signals.hpp"  // uptime_observation (shared cross-platform os.uptime_report)
#include "dex_perf_breach.hpp"    // breach_update, kCpuBreach/kMemoryBreach, *_observation
#include "dex_win_poll.hpp"       // DiskLevel, latch_should_emit

#include <yuzu/log_token.hpp> // log_key_token: subject/reason come from journal fields (F59)
#include <yuzu/agent/dex_rate_limiter.hpp> // DexRateLimiter — per-obs_type hourly emit cap

#include <sys/statvfs.h>
#include <sys/wait.h> // WIFEXITED / WEXITSTATUS — journalctl exit status drives cursor re-baseline

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <filesystem> // /sys/devices/system/cpu/cpu* enumeration for the throttle poll
#include <fstream>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility> // std::exchange (Pipe move/close)

#include <spdlog/spdlog.h>

namespace yuzu::agent {
namespace {

std::int64_t now_unix() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Monotonic seconds for the poll CADENCE only — immune to wall-clock steps (NTP
// step-back, VM snapshot-resume) that would otherwise stall the loop until the old
// stamp is re-passed (Gate-4 UP-12). The emitted observation timestamp still uses
// now_unix() (wall clock) — that one must reflect real time, not uptime.
std::int64_t steady_now() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

// Read a small /proc pseudo-file whole. /proc/stat, /proc/meminfo and
// /proc/mounts report size 0 but stream their content; they are a few KiB at most
// and must be read in one shot (the parsers expect a complete snapshot).
std::optional<std::string> read_proc_file(const char* path) {
    std::ifstream f(path);
    if (!f.is_open())
        return std::nullopt;
    std::ostringstream ss;
    ss << f.rdbuf();
    if (ss.fail() || f.bad()) // empty / errored read — treat as unreadable (review MEDIUM)
        return std::nullopt;
    return ss.str();
}

// RAII for a popen() pipe — pclose on every exit path (the macOS poll_oslog
// pattern). The journalctl command is built from internal constants + the
// journald-generated cursor, never operator input, so there is no shell-injection
// surface. close() exposes the command's exit status so the caller can tell a
// successful read (exit 0, including a quiet poll with no new entries) from a
// journalctl that could NOT seek the cursor (non-zero) and must re-baseline.
class Pipe {
public:
    explicit Pipe(std::FILE* f) noexcept : f_(f) {}
    ~Pipe() { close(); }
    Pipe(const Pipe&) = delete;
    Pipe& operator=(const Pipe&) = delete;
    Pipe(Pipe&& o) noexcept : f_(std::exchange(o.f_, nullptr)) {}
    Pipe& operator=(Pipe&&) = delete;

    explicit operator bool() const noexcept { return f_ != nullptr; }
    std::FILE* get() const noexcept { return f_; }

    // Close the pipe and return the command's exit status: WEXITSTATUS on a normal
    // exit, 128+signal if it was killed (so a `timeout`-killed wedge reads non-zero),
    // -1 if already closed / pclose itself failed. Idempotent — the destructor calls
    // it again harmlessly.
    int close() noexcept {
        if (!f_)
            return -1;
        const int rc = ::pclose(std::exchange(f_, nullptr));
        if (rc == -1)
            return -1;
        if (WIFEXITED(rc))
            return WEXITSTATUS(rc);
        if (WIFSIGNALED(rc))
            return 128 + WTERMSIG(rc);
        return rc ? 1 : 0;
    }

private:
    std::FILE* f_ = nullptr;
};

Pipe open_pipe(const std::string& cmd) { return Pipe(::popen(cmd.c_str(), "r")); }

/// The Linux DEX observer: a single owned poll thread (the WinStatePoller
/// lifetime — stop() joins it, the sink is set before the thread starts and
/// cleared after the join, so no callback can outlive the object). All signals
/// reuse the existing pure decision + observation builders, so a Linux server is
/// observed identically to Windows/macOS in the same /dex buckets.
class LinuxDexObserver final : public ISignalObserver {
public:
    ~LinuxDexObserver() override { stop(); }

    bool start(SignalSink sink, std::function<void()> on_error) override {
        if (thread_.joinable())
            return true; // already armed (idempotent)
        sink_ = std::move(sink);
        on_error_ = std::move(on_error); // fired at runtime if /proc becomes unreadable (HIGH-3)
        stopping_ = false;
        thread_ = std::thread([this] { run(); });
        spdlog::info("dex_observer(linux): armed — /proc perf + storage + journald + uptime poll");
        return true;
    }

    void stop() override {
        {
            std::lock_guard lk(mu_);
            stopping_ = true;
        }
        cv_.notify_all();
        if (thread_.joinable())
            thread_.join();
        sink_ = nullptr;
        on_error_ = nullptr;
    }

    int armed_channels() const override { return thread_.joinable() ? 1 : 0; }

private:
    void run() {
        // First poll 60 s after arm (never at-arm — arm-time work delays agent
        // startup), then each source keeps its own cadence. Mirrors WinStatePoller.
        {
            const std::int64_t now = steady_now();
            last_perf_poll_ = now - win::kPerfSampleIntervalSeconds + kFirstPollDelaySeconds;
            last_disk_poll_ = now - kDiskIntervalSeconds + kFirstPollDelaySeconds;
            last_journald_poll_ = now - kJournaldIntervalSeconds + kFirstPollDelaySeconds;
            last_uptime_poll_ = now - kUptimeIntervalSeconds + kFirstPollDelaySeconds;
        }
        // Seed the journald cursor at arm — on THIS poll thread, so it does NOT delay
        // agent startup (start() has already returned), unlike the perf/disk/uptime
        // sources whose first poll is deferred 60 s. Seeding here closes the gap where
        // a reliability event in the first journald interval after arm (e.g. a service
        // that crashes right after boot) would otherwise be skipped to the +60 s tail.
        // poll_journald()'s empty-cursor branch is the retry path if this finds no
        // journal (non-systemd host / transient miss). The drain classifier is
        // exception-free in practice, but its string/vector growth could in principle
        // throw, and this pre-loop seed sits OUTSIDE the for-loop's per-iteration guard
        // — so it carries its own try/catch (the no-unwind invariant is structural,
        // from the guards, not from any nothrow guarantee).
        try {
            seed_journal_cursor();
        } catch (...) {
            spdlog::warn("dex_observer(linux): initial journald cursor seed failed, continuing");
        }
        for (;;) {
            const std::int64_t next = std::min({last_perf_poll_ + win::kPerfSampleIntervalSeconds,
                                                last_disk_poll_ + kDiskIntervalSeconds,
                                                last_journald_poll_ + kJournaldIntervalSeconds,
                                                last_uptime_poll_ + kUptimeIntervalSeconds});
            const auto wait_s =
                std::chrono::seconds(std::max(next - steady_now(), std::int64_t{1}));
            {
                std::unique_lock lk(mu_);
                if (cv_.wait_for(lk, wait_s, [this] { return stopping_; }))
                    return; // stop() requested
            }
            const std::int64_t now = steady_now();
            // A poll must NEVER unwind out of this thread (the file invariant): an
            // allocation failure — most likely exactly when measuring memory pressure —
            // would otherwise std::terminate the whole agent. Catch-and-continue keeps
            // the thread alive (so the observer is not silently dead); the next tick
            // re-baselines. (Bounding statvfs against a hung block device is a separate,
            // tracked follow-up — a D-state stall throws nothing to catch here.)
            try {
                if (now - last_perf_poll_ >= win::kPerfSampleIntervalSeconds) {
                    last_perf_poll_ = now;
                    poll_perf();
                }
                if (now - last_disk_poll_ >= kDiskIntervalSeconds) {
                    last_disk_poll_ = now;
                    poll_disks();
                    poll_throttle(); // CPU thermal throttling — same slow hardware-state cadence
                }
                if (now - last_journald_poll_ >= kJournaldIntervalSeconds) {
                    last_journald_poll_ = now;
                    poll_journald();
                }
                if (now - last_uptime_poll_ >= kUptimeIntervalSeconds) {
                    last_uptime_poll_ = now;
                    poll_uptime();
                }
            } catch (const std::exception& e) {
                spdlog::warn("dex_observer(linux): poll iteration failed, continuing: {}",
                             e.what());
            } catch (...) {
                spdlog::warn("dex_observer(linux): poll iteration failed (unknown), continuing");
            }
        }
    }

    // Sustained CPU + commit-charge breaches via the SAME hysteresis + builders as
    // Windows (dex_perf_breach). CPU needs two readings for the busy% delta; the
    // first poll (and any unreadable one) only re-baselines — breach_update treats
    // the invalid sample as a gap (the latch holds, no re-fire). Emission is
    // bounded by the sustain/recover windows, so no rate cap is needed.
    void poll_perf() {
        bool cpu_valid = false;
        double cpu_pct = 0.0;
        if (const auto stat = read_proc_file("/proc/stat")) {
            const lnx::CpuJiffies cur = lnx::parse_proc_stat(*stat);
            if (const auto pct = lnx::cpu_busy_pct(prev_cpu_, cur)) {
                cpu_pct = *pct;
                cpu_valid = true;
            }
            prev_cpu_ = cur; // baseline the next interval (even if this one was invalid)
            proc_stat_fail_streak_ = 0; // a good read clears the disarm streak
        } else {
            prev_cpu_ = lnx::CpuJiffies{}; // unreadable — drop the baseline
            // Flag the observer unhealthy only after PERSISTENT failure. The Windows
            // on_error fires on terminal subscription death; a Linux /proc/stat read miss
            // is usually TRANSIENT (a momentary EMFILE, a brief seccomp/mount-ns blip),
            // and the poll thread re-baselines and resumes next tick — so a single miss
            // must NOT latch armed=0 (that produced fleet-wide false-disarm alerts, sre
            // Gate-6). Disarm only after kProcFailDisarmThreshold consecutive misses.
            // (on_error is one-way today; recovery-to-armed is a tracked follow-up.)
            if (++proc_stat_fail_streak_ >= kProcFailDisarmThreshold && on_error_)
                on_error_();
        }
        if (const auto avg = win::breach_update(cpu_breach_, cpu_pct, cpu_valid, win::kCpuBreach))
            emit(win::cpu_sustained_observation(*avg));

        // Commit charge vs commit limit — Linux's direct analogue of the Windows
        // commit/limit signal, so memory_pressure_observation's "commit charge …
        // of limit" wording is correct, not relabelled. SKIPPED under
        // vm.overcommit_memory=1 ("always"): there CommitLimit is advisory and
        // Committed_AS routinely exceeds it on healthy DB/Redis/HPC hosts, so the
        // ratio would false-positive-storm (Gate-4 UP-7). A read failure leaves the
        // signal enabled (fail-safe toward keeping it). Modes 0/2 keep it meaningful.
        bool mem_valid = false;
        double mem_pct = 0.0;
        const auto oc = read_proc_file("/proc/sys/vm/overcommit_memory");
        if (!(oc && lnx::overcommit_is_always(*oc))) {
            if (const auto mem = read_proc_file("/proc/meminfo")) {
                if (const auto pct = lnx::parse_commit_pct(*mem)) {
                    mem_pct = *pct;
                    mem_valid = true;
                }
            }
        }
        if (const auto avg =
                win::breach_update(mem_breach_, mem_pct, mem_valid, win::kMemoryBreach))
            emit(win::memory_pressure_observation(*avg));

        // Disk service time (await) — the Linux analogue of the Windows
        // IOCTL_DISK_PERFORMANCE per-IO latency, summed over the whole physical disks
        // (/proc/diskstats reports times already in ms). Same hysteresis + 25 ms
        // threshold as Windows (win::kDiskLatBreach) via the SAME breach_update, so a
        // slow Linux disk renders identically to a slow Windows one. The first poll
        // (and any unreadable one) only re-baselines — disk_await_ms treats it as a gap.
        bool disk_valid = false;
        double disk_ms = 0.0;
        if (const auto ds = read_proc_file("/proc/diskstats")) {
            const lnx::DiskIoTotals cur = lnx::parse_diskstats(*ds);
            if (const auto await = lnx::disk_await_ms(prev_disk_, cur)) {
                disk_ms = *await;
                disk_valid = true;
            }
            prev_disk_ = cur; // baseline the next interval (even if this one was invalid)
        } else {
            prev_disk_ = lnx::DiskIoTotals{}; // unreadable — drop the baseline
        }
        if (const auto avg =
                win::breach_update(disk_lat_breach_, disk_ms, disk_valid, win::kDiskLatBreach))
            emit(win::disk_latency_observation(*avg));
    }

    // CPU thermal throttling via /sys — a transition-latched hardware-state poll (the
    // storage.low shape, NOT a sustained breach). core_throttle_count is a monotonic
    // per-core count of throttling episodes; summed across cores, an INCREASE since the
    // last poll means the CPU throttled this interval. Latch on entry, suppress while it
    // keeps throttling, re-arm on an interval with no new throttling. No thermal_throttle
    // interface (VM / non-x86) → no read → never emits (no false positive). Reused
    // hw.cpu_throttled obs_type (the Windows Kernel-Processor-Power 37 analogue).
    void poll_throttle() {
        // PER-CORE counts (cpuN -> core_throttle_count), NOT a single sum: a summed
        // counter cannot distinguish a genuine throttle from a CPU offlining/onlining
        // (vCPU hotplug, SMT toggle), where the sum drops then jumps and fabricates a
        // throttle on the re-online edge (Gate-4 UP-5 / Gate-8). Comparing per-core and
        // counting ONLY cores present in BOTH samples makes hotplug invisible.
        lnx::ThrottleCounts cur;
        std::error_code ec;
        const std::filesystem::path cpus{"/sys/devices/system/cpu"};
        for (std::filesystem::directory_iterator it{cpus, ec}, end; !ec && it != end;
             it.increment(ec)) {
            std::string name = it->path().filename().string();
            if (name.size() <= 3 || name.compare(0, 3, "cpu") != 0)
                continue;
            if (!std::all_of(name.begin() + 3, name.end(),
                             [](unsigned char c) { return c >= '0' && c <= '9'; }))
                continue; // "cpu0".."cpuN" only — skip "cpufreq", "cpuidle", …
            const std::string path =
                (it->path() / "thermal_throttle" / "core_throttle_count").string();
            if (const auto content = read_proc_file(path.c_str()))
                if (const auto v = lnx::parse_throttle_count(*content))
                    cur.emplace(std::move(name), *v);
        }
        if (cur.empty())
            return; // no thermal_throttle interface — leave prev untouched, never emit
        if (!prev_throttle_counts_.empty()) {
            // Throttling iff SOME core present in both samples incremented (pure +
            // unit-tested in dex_linux_sysfs). A core that appeared (re-online) or
            // disappeared (offline) is never compared, so hotplug cannot fire a spurious
            // throttle. The latch re-arms only when no common core increments — bounded
            // to one observation per throttling episode.
            const bool throttling = lnx::throttle_increased(prev_throttle_counts_, cur);
            if (win::latch_should_emit(throttling, /*valid=*/true, throttle_reported_)) {
                SignalObservation o;
                o.obs_type = "hw.cpu_throttled";
                o.subject = "cpu";
                o.reason = "thermal-throttle";
                o.sentence = "CPU thermal throttling detected";
                emit(std::move(o));
            }
        }
        prev_throttle_counts_ = std::move(cur);
    }

    // Poll-and-latch storage.low over real local filesystems, via the SAME pure
    // decision functions as Windows. parse_storage_mounts whitelists block-backed
    // fstypes (so no squashfs/snap "100% by design" noise and no statvfs() on a
    // potentially-hung network mount), and a failed statvfs leaves the level
    // invalid → low_disk_observation nullopt → the latch neither emits nor clears
    // (UP-5: a transient read failure must not re-fire). Paths with octal-escaped
    // characters (\040) are statvfs'd as-is and simply skipped if that fails — a
    // rare, safe omission for v1.
    void poll_disks() {
        const auto mounts = read_proc_file("/proc/mounts");
        if (!mounts)
            return;
        std::unordered_set<std::string> current;
        for (const auto& m : lnx::parse_storage_mounts(*mounts)) {
            // Latch identity is the backing DEVICE (the dedup key + the subject source),
            // NOT the mount path: keying by path would re-fire a duplicate storage.low for
            // the same device if it is remounted at a different path (UP-8, Gate-4).
            current.insert(m.device);
            win::DiskLevel level;
            struct statvfs vfs{};
            if (::statvfs(m.path.c_str(), &vfs) == 0 && vfs.f_blocks > 0) {
                const std::uint64_t bs = vfs.f_frsize ? vfs.f_frsize : vfs.f_bsize;
                level.valid = true;
                level.total_bytes = static_cast<std::uint64_t>(vfs.f_blocks) * bs;
                // f_bavail = blocks free to unprivileged users (the "disk is full"
                // signal), not f_bfree which includes the root-reserved slack.
                level.free_bytes = static_cast<std::uint64_t>(vfs.f_bavail) * bs;
            }
            // Single chokepoint: subject = the backing-device basename, NEVER the mount
            // path (a path carries usernames / tenant / project names — DEX edge-privacy,
            // dex-signal-catalog.md §"Privacy / works-council contract"). m.path is used
            // ONLY for the local statvfs() above; it is never passed to the observation, so
            // it cannot be emitted, serialized, or logged. The [dex][privacy] test guards
            // this exact call.
            const auto obs = lnx::storage_low_observation(m, level);
            bool& reported = disk_low_reported_[m.device];
            if (win::latch_should_emit(obs.has_value(), level.valid, reported))
                emit(*obs);
        }
        // Drop latch entries for devices that have gone away, so the map stays bounded
        // by the live device count, not every device ever seen (review MEDIUM).
        std::erase_if(disk_low_reported_,
                      [&](const auto& kv) { return !current.contains(kv.first); });
    }

    // Seed the journald cursor at the journal tail and emit NOTHING (no history
    // replay). drain advances journal_cursor_; its observations are deliberately
    // DISCARDED so a crash/OOM that happens to be the tail entry is not re-reported
    // as a fresh event at arm. Called once at run() start (closing the at-arm gap)
    // and as poll_journald()'s retry path when the cursor is still empty (non-systemd
    // host: the shell-out yields no output, the cursor never seeds, the source quietly
    // no-ops). Both callers are exception-guarded (run()'s pre-loop try and the
    // for-loop's per-iteration try), so a drain allocation failure cannot unwind the
    // poll thread — this method itself makes no nothrow promise.
    void seed_journal_cursor() {
        if (const Pipe p = open_pipe(lnx::journald_baseline_query()))
            (void)lnx::drain_journal_pipe(p.get(), journal_cursor_);
    }

    // Poll the systemd journal for new reliability events. The cursor is seeded at the
    // journal tail at arm (seed_journal_cursor); each poll then reads strictly after it
    // (journalctl --after-cursor is exclusive → no boundary de-dup). MESSAGE_ID matching
    // yields one canonical entry per failure; the `+ _TRANSPORT=kernel` group carries the
    // OOM line (no stable MESSAGE_ID) and is parsed-and-mostly-dropped. No libsystemd:
    // journalctl is a runtime shell-out. The cursor advances only after a clean read, so a
    // throw mid-loop re-polls the same window next tick; and if journalctl exits non-zero
    // (the cursor rotated out of the journal, or a `timeout`-killed wedge), the cursor is
    // dropped and re-baselined — without that, a stale cursor would silently never match
    // again (permanent silence). A quiet poll with no new entries exits 0, so it keeps its
    // cursor.
    void poll_journald() {
        // Evict debounce entries older than the window FIRST, every cycle (the
        // age-keyed analogue of poll_disks()'s std::erase_if on disk_low_reported_):
        // a stamp past the window can no longer suppress, so it is pure bloat. One
        // MONOTONIC reading drives both eviction and the debounce — the window is a
        // timer, immune to wall-clock steps. (The EMITTED observation's timestamp_unix,
        // in emit(), stays wall-clock — that one is a real time, not a timer.)
        const std::int64_t now = steady_now();
        journal_debounce_.evict_stale(now);

        if (journal_cursor_.empty()) {
            seed_journal_cursor(); // arm-time seed missed (non-systemd / transient) — retry
            return;
        }

        const auto cmd = lnx::build_journald_after_cursor_query(journal_cursor_);
        if (!cmd) {
            journal_cursor_.clear(); // cursor held a quote (never happens for a real
            return;                  // __CURSOR) — drop it and re-baseline next tick
        }
        Pipe pipe = open_pipe(*cmd);
        if (!pipe) {
            spdlog::warn("dex_observer(linux): popen(journalctl) failed — journald poll skipped");
            return;
        }
        // drain advances journal_cursor_ to the newest entry it reads; a throw or short
        // read leaves it at the last good line, so the same window is re-polled. The
        // debounce collapses a flapping unit/process to one observation per window.
        auto observations = lnx::drain_journal_pipe(pipe.get(), journal_cursor_);
        const int rc = pipe.close(); // exit status AFTER draining stdout to EOF
        // Emit whatever was read FIRST (a timeout mid-read still yields real events),
        // then re-baseline on a non-zero exit so a cursor the journal rotated past does
        // not wedge the source in permanent silence.
        for (auto& obs : observations)
            if (journal_debounce_.should_emit(obs.obs_type, obs.subject, now))
                emit(std::move(obs));
        if (rc != 0) {
            spdlog::warn(
                "dex_observer(linux): journalctl exited {} — dropping journald cursor to re-baseline",
                rc);
            journal_cursor_.clear();
        }
    }

    // os.uptime_report — the cross-platform uptime/reboot heartbeat (the Windows
    // EventLog 6013 / macOS sysctl-boottime equivalent). Interval-gated (hourly,
    // trendable) and timer-driven, not at-arm. /proc/uptime is unprivileged; boot
    // time = now - uptime, fed to the SAME builder macOS uses so the observation is
    // identical across OSes (parity). Bounded by the cadence — no debounce needed.
    void poll_uptime() {
        const auto txt = read_proc_file("/proc/uptime");
        if (!txt)
            return;
        const auto up = lnx::parse_proc_uptime(*txt);
        if (!up)
            return;
        const std::int64_t now = now_unix();
        if (auto obs = macos::uptime_observation(now - static_cast<std::int64_t>(*up), now))
            emit(std::move(*obs));
    }

    // Stamp platform + delivery time centrally (an empty platform would vanish from
    // the by-OS panel; "linux" is the render token, matching dex_routes os_label),
    // then enforce the per-obs_type hourly cap before the sink — a crash-looping
    // process or flapping unit (which the debounce only collapses to one-per-window,
    // not one-per-hour) must not flood the wire (be kind to the network, the parity
    // of the Windows/macOS collectors which both cap). The cap keys off the catalogue
    // (process.crashed=120, memory.exhausted=12, os.uptime_report=4, …; 60 default).
    // Bucketed on the wall-clock timestamp just stamped above, matching macOS.
    void emit(SignalObservation obs) {
        obs.platform = "linux";
        obs.timestamp_unix = now_unix();
        const RateDecision decision = rate_limiter_.check(obs.obs_type, obs.timestamp_unix);
        if (decision == RateDecision::DropAndWarn)
            spdlog::warn("dex_observer(linux): {}/hour cap reached for {} — dropping until next hour",
                         dex_obs_cap_per_hour(obs.obs_type), obs.obs_type);
        if (decision != RateDecision::Emit)
            return; // over cap this hour — drop
        spdlog::info("dex_observer(linux): observed {} subject='{}' reason={}", obs.obs_type,
                     ::yuzu::log_key_token(obs.subject), ::yuzu::log_key_token(obs.reason));
        try {
            sink_(obs);
        } catch (...) {
            // The sink does a network write — a failure must not kill the poll thread.
        }
    }

    static constexpr std::int64_t kFirstPollDelaySeconds = 60;
    static constexpr std::int64_t kDiskIntervalSeconds = 600;     // 10 min (the WinStatePoller cadence)
    static constexpr std::int64_t kJournaldIntervalSeconds = 60;  // reliability events want low latency
    static constexpr std::int64_t kJournaldDebounceSeconds = 300; // collapse a flapping unit/process
    static constexpr std::int64_t kUptimeIntervalSeconds = 3600;  // hourly uptime/reboot heartbeat
    static constexpr int kProcFailDisarmThreshold = 3; // consecutive /proc/stat misses before disarm

    std::mutex mu_;
    std::condition_variable cv_;
    bool stopping_ = false;
    std::thread thread_;
    SignalSink sink_; // set before the thread starts, cleared after join — stable in run()
    std::function<void()> on_error_; // disarms dex_health_ after persistent /proc failure (HIGH-3)
    std::int64_t last_perf_poll_ = 0;
    std::int64_t last_disk_poll_ = 0;
    std::int64_t last_journald_poll_ = 0;
    std::int64_t last_uptime_poll_ = 0;
    int proc_stat_fail_streak_ = 0;                          // consecutive /proc/stat read misses
    lnx::CpuJiffies prev_cpu_;                               // valid=false until the first read
    lnx::DiskIoTotals prev_disk_;                            // valid=false until the first diskstats read
    win::BreachState cpu_breach_, mem_breach_, disk_lat_breach_; // sustained-breach latches
    lnx::ThrottleCounts prev_throttle_counts_;             // per-core core_throttle_count, prior snapshot
    bool throttle_reported_ = false;                        // hw.cpu_throttled poll-and-latch
    std::unordered_map<std::string, bool> disk_low_reported_; // per-device storage.low latch
    std::string journal_cursor_;                              // "" until baselined at the journal tail
    lnx::JournalDebounce journal_debounce_{kJournaldDebounceSeconds}; // per-(type,subject) flap collapse
    DexRateLimiter rate_limiter_;                             // per-obs_type hourly emit cap (all sources)
};

} // namespace

std::unique_ptr<ISignalObserver> make_linux_dex_observer() {
    return std::make_unique<LinuxDexObserver>();
}

} // namespace yuzu::agent

#endif // __linux__
