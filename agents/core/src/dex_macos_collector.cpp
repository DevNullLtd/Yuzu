/**
 * dex_macos_collector.cpp — the macOS DEX collection engine (ISignalObserver).
 *
 * The macOS analogue of dex_observer.cpp's Windows EvtSubscribe engine. macOS has
 * no single push-event API; this engine uses the two privilege-light mechanisms
 * that cover the report-shaped + scalar signals WITHOUT an Endpoint Security
 * entitlement or Full Disk Access (reading the agent user's own
 * ~/Library/Logs/DiagnosticReports and the world-readable
 * /Library/Logs/DiagnosticReports needs neither):
 *
 *   1. kqueue EVFILT_VNODE folder-watch over the two DiagnosticReports
 *      directories — idle until a `.ips` / `.diag` report is written, then a
 *      rescan picks up the new files (crash, hang, panic, jetsam, resource).
 *   2. A one-shot sysctl(KERN_BOOTTIME) read at arm → the os.uptime_report
 *      scalar (the EventLog-6013 equivalent).
 *
 * The fiddly field extraction lives in the pure, cross-platform-tested
 * dex_macos_signals.{hpp,cpp}; this file is the impure mechanism. Lifetime is
 * deliberately SIMPLE (unlike the Windows engine's leaked-shared_ptr / in-flight
 * drain machinery, which exists only because EvtSubscribe callbacks run on an OS
 * threadpool that outlives the object): this engine owns its own thread, stop()
 * wakes it via EVFILT_USER and joins, and the sink is only ever touched by that
 * thread between start() and join — so no callback can fire after teardown.
 */

#include <yuzu/agent/dex_observer.hpp>
#include <yuzu/agent/fork_lock.hpp> // global_fork_lock() — BR-001 popen guard (K-DEX-2)

#if defined(__APPLE__)

#include "dex_macos_iokit.hpp"
#include "dex_macos_oslog.hpp"
#include "dex_macos_signals.hpp"

#include <spdlog/spdlog.h>

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <exception>
#include <fstream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <sys/event.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <unistd.h>

namespace yuzu::agent {
namespace {

constexpr const char* kSystemDiagDir = "/Library/Logs/DiagnosticReports";
constexpr std::uintptr_t kStopIdent = 1;  // EVFILT_USER ident — wakes run() to exit
constexpr std::uintptr_t kTimerIdent = 2; // EVFILT_TIMER ident — periodic safety rescan
constexpr int kRescanSeconds = 60;        // backstop a missed vnode event
constexpr int kMaxReadRetries = 3;        // bounded retries on an unreadable (mid-write) file
constexpr std::int64_t kUptimeIntervalSeconds = 3600; // os.uptime_report cadence (trendable)
constexpr std::int64_t kIokitIntervalSeconds = 3600;    // battery/SMART poll cadence (slow-changing)
constexpr std::int64_t kResourceIntervalSeconds = 600;  // disk/thermal/memory cadence (fluctuating)

std::int64_t now_unix() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::int64_t boot_unix() {
    struct timeval bt{};
    std::size_t len = sizeof(bt);
    int mib[2] = {CTL_KERN, KERN_BOOTTIME};
    if (::sysctl(mib, 2, &bt, &len, nullptr, 0) == 0 && bt.tv_sec > 0)
        return static_cast<std::int64_t>(bt.tv_sec);
    return 0;
}

std::string user_diag_dir() {
    if (const char* home = ::getenv("HOME"); home && *home)
        return std::string(home) + "/Library/Logs/DiagnosticReports";
    return {};
}

// Local-time "YYYY-MM-DD HH:MM:SS" — the format `log show --start` accepts and the
// 19-char prefix of an ndjson `timestamp` ("2026-06-09 16:03:20.238403+0100"), so
// checkpoint comparisons are a plain lexicographic compare in one fixed TZ.
std::string format_checkpoint(std::int64_t t) {
    const std::time_t tt = static_cast<std::time_t>(t);
    std::tm tm{};
    ::localtime_r(&tt, &tm);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    return buf;
}

// The second-precision timestamp out of an ndjson line, by string scan (cheap —
// avoids a full JSON parse just to order/dedup): the 19 chars after "timestamp":".
std::string oslog_line_timestamp(const std::string& line) {
    const std::size_t k = line.find("\"timestamp\":\"");
    if (k == std::string::npos || k + 13 + 19 > line.size())
        return {};
    return line.substr(k + 13, 19);
}

bool ends_with(const std::string& s, std::string_view suf) {
    return s.size() >= suf.size() && s.compare(s.size() - suf.size(), suf.size(), suf) == 0;
}

bool is_report_file(const std::string& name) {
    return ends_with(name, ".ips") || ends_with(name, ".diag");
}

// Read a whole file; "" on open/short failure (caller treats "" as not-yet-readable).
std::string read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in)
        return {};
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

// RAII owner for a popen pipe: pclose runs on every exit path, including an
// exception thrown by the caller's read loop (string growth → bad_alloc) or by a
// sink callback invoked mid-read. Governance B1: a manual pclose with a throwing
// statement between popen and the close leaks the pipe AND lets the exception
// escape the worker thread → std::terminate. The deleter is noexcept(pclose).
using PipeHandle = std::unique_ptr<FILE, decltype(&::pclose)>;
inline PipeHandle open_pipe(const std::string& cmd) {
    // BR-001 (review K-DEX-2): popen() forks internally, so it is itself a
    // launcher and must not overlap another launcher's non-CLOEXEC
    // pipe-creation window. The hazard is CROSS-THREAD, not within this DEX
    // worker: a concurrent run_bounded_subprocess() on another thread can fork
    // while this popen()'s pipe fds are not yet CLOEXEC (or vice versa),
    // wedging one side's read on a leaked fd. Take the process-global fork lock
    // across JUST the popen() call — never across the read loop or pclose (see
    // fork_lock.hpp's contract). Precedent: trigger_engine.cpp's macOS
    // query_service_status uses exactly this guard.
    FILE* fp = nullptr;
    {
        std::lock_guard<std::mutex> fork_pipe_lock(yuzu::agent::global_fork_lock());
        fp = ::popen(cmd.c_str(), "r");
    }
    return PipeHandle(fp, &::pclose);
}

// Run a command and capture its full stdout (bounded — these are one-shot status
// tools: diskutil, system_profiler). "" on popen failure. The commands are
// internal literals (no user input) so there is no injection surface.
std::string capture_command(const std::string& cmd) {
    PipeHandle pipe = open_pipe(cmd);
    if (!pipe)
        return {};
    std::string out;
    char buf[4096];
    while (std::fgets(buf, sizeof(buf), pipe.get()))
        out += buf;
    return out; // pclose runs via PipeHandle dtor (also on an exceptional unwind)
}

// Report filenames (not paths) directly in `dir` — excludes the "Retired"
// subdirectory and anything that is not a .ips/.diag (filtered by extension).
std::vector<std::string> list_reports(const std::string& dir) {
    std::vector<std::string> out;
    DIR* d = ::opendir(dir.c_str());
    if (!d)
        return out;
    while (dirent* e = ::readdir(d)) {
        std::string name = e->d_name;
        // Skip ALL dotfiles, not just "." / "..": ReportCrash writes a report to a
        // hidden temp ".<name>.ips" and atomically renames it to "<name>.ips" when
        // complete. Matching the temp would (a) read a half-written report and
        // (b) double-count (temp path + final path = two seen-set entries). Only
        // the final, atomically-renamed file is ever processed.
        if (name.empty() || name[0] == '.' || !is_report_file(name))
            continue;
        out.push_back(std::move(name));
    }
    ::closedir(d);
    return out;
}

/// macOS DEX signal engine. One worker thread blocking in kevent(); folder-watch
/// vnode events (or the periodic timer) trigger a rescan that parses any newly
/// appeared report and emits it through the sink. platform + timestamp are
/// stamped centrally here so no per-type extractor can forget them (a signal with
/// an empty platform would vanish from the by-OS panel).
class MacosDexObserver final : public ISignalObserver {
public:
    ~MacosDexObserver() override { stop(); }

    bool start(SignalSink sink, std::function<void()> on_error) override {
        std::lock_guard lk(mu_);
        if (running_)
            return true;
        sink_ = std::move(sink);
        on_error_ = std::move(on_error);

        dirs_.clear();
        if (std::string u = user_diag_dir(); !u.empty())
            dirs_.push_back(std::move(u));
        dirs_.emplace_back(kSystemDiagDir);

        // Future-only (mirrors EvtSubscribeToFutureEvents): seed the seen-set with
        // every report that already exists so historical reports are NOT re-emitted
        // as if they just happened.
        for (const auto& dir : dirs_)
            for (const auto& f : list_reports(dir))
                seen_.insert(dir + "/" + f);

        kq_ = ::kqueue();
        if (kq_ < 0) {
            spdlog::warn("dex_observer(macos): kqueue() failed (errno={}) — DEX collection disabled",
                         errno);
            sink_ = nullptr;
            on_error_ = nullptr;
            return false;
        }

        int watched = 0;
        for (const auto& dir : dirs_) {
            const int fd = ::open(dir.c_str(), O_RDONLY | O_EVTONLY);
            if (fd < 0) {
                spdlog::warn("dex_observer(macos): cannot watch {} (errno={}) — skipped", dir,
                             errno);
                continue;
            }
            dir_fds_.push_back(fd);
            struct kevent ev{};
            EV_SET(&ev, fd, EVFILT_VNODE, EV_ADD | EV_CLEAR,
                   NOTE_WRITE | NOTE_EXTEND | NOTE_LINK, 0, nullptr);
            ::kevent(kq_, &ev, 1, nullptr, 0, nullptr);
            ++watched;
        }

        // Stop trigger + periodic safety rescan. The EVFILT_USER stop filter is
        // load-bearing for clean shutdown: if its registration fails, stop()'s
        // NOTE_TRIGGER is a no-op and join() hangs forever (governance cs-S1).
        // Treat a registration error as fatal to arming and tidy up.
        struct kevent ctl[2]{};
        EV_SET(&ctl[0], kStopIdent, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, nullptr);
        EV_SET(&ctl[1], kTimerIdent, EVFILT_TIMER, EV_ADD, NOTE_SECONDS, kRescanSeconds, nullptr);
        if (::kevent(kq_, ctl, 2, nullptr, 0, nullptr) < 0) {
            spdlog::warn("dex_observer(macos): cannot register stop/timer kevents (errno={}) — DEX "
                         "collection disabled (clean shutdown could not be guaranteed)",
                         errno);
            for (const int fd : dir_fds_)
                ::close(fd);
            dir_fds_.clear();
            ::close(kq_);
            kq_ = -1;
            sink_ = nullptr;
            on_error_ = nullptr;
            return false;
        }

        if (watched == 0) {
            spdlog::warn("dex_observer(macos): no DiagnosticReports directory watchable — "
                         "DEX collection disabled");
            ::close(kq_);
            kq_ = -1;
            sink_ = nullptr;
            on_error_ = nullptr;
            return false;
        }

        // Seed the unified-log checkpoint to NOW so the first poll is future-only
        // (consistent with the report watcher's seen-set seeding).
        oslog_checkpoint_ = format_checkpoint(now_unix());

        armed_ = watched;
        running_ = true;
        thread_ = std::thread([this] { run(); });
        spdlog::info(
            "dex_observer(macos): armed — {} report dir(s) watched + uptime scalar + unified log",
            watched);
        return true;
    }

    void stop() override {
        {
            std::lock_guard lk(mu_);
            if (!running_) {
                // start() may have partially set up (kq_ open) before failing; tidy.
                cleanup_locked();
                return;
            }
            running_ = false;
        }
        // Wake the worker out of kevent() so it can observe running_ == false.
        if (kq_ >= 0) {
            struct kevent w{};
            EV_SET(&w, kStopIdent, EVFILT_USER, 0, NOTE_TRIGGER, 0, nullptr);
            ::kevent(kq_, &w, 1, nullptr, 0, nullptr);
        }
        if (thread_.joinable())
            thread_.join(); // no sink access can outlive this join
        std::lock_guard lk(mu_);
        cleanup_locked();
    }

    int armed_channels() const override { return armed_; }

private:
    struct RateBucket {
        std::int64_t hour{0};
        int count{0};
        bool warned{false};
    };

    void cleanup_locked() {
        for (const int fd : dir_fds_)
            ::close(fd);
        dir_fds_.clear();
        if (kq_ >= 0) {
            ::close(kq_);
            kq_ = -1;
        }
        sink_ = nullptr;
        on_error_ = nullptr;
        seen_.clear();
        retry_.clear();
        oslog_checkpoint_.clear();
        oslog_seen_at_checkpoint_.clear();
        last_iokit_poll_ = 0;
        smart_bad_reported_ = false;
        battery_bad_reported_ = false;
        last_resource_poll_ = 0;
        disk_low_reported_ = false;
        thermal_reported_ = false;
        mem_pressure_reported_ = false;
        armed_ = 0;
    }

    int cap_for(const std::string& obs_type) const {
        if (obs_type == "process.crashed" || obs_type == "process.hung")
            return 120;
        if (obs_type == "os.bugcheck")
            return 30;
        if (obs_type == "memory.exhausted")
            return 12;
        if (obs_type == "process.resource_limit")
            return 30;
        return 60;
    }

    // Stamp platform + delivery time centrally, rate-cap, then hand to the sink.
    // Called only from the worker thread, so rate_ needs no lock and sink_ is
    // stable for the lifetime of run() (set before the thread, cleared after join).
    void emit(SignalObservation obs) {
        obs.platform = "macos";
        obs.timestamp_unix = now_unix();

        const std::int64_t hour = obs.timestamp_unix / 3600;
        auto& b = rate_[obs.obs_type];
        if (b.hour != hour) {
            b.hour = hour;
            b.count = 0;
            b.warned = false;
        }
        if (++b.count > cap_for(obs.obs_type)) {
            if (!b.warned) {
                b.warned = true;
                spdlog::warn("dex_observer(macos): rate cap hit for {} ({}/h) — dropping until the "
                             "next hour bucket",
                             obs.obs_type, cap_for(obs.obs_type));
            }
            return;
        }
        spdlog::info("dex_observer(macos): observed {} subject='{}'{}", obs.obs_type, obs.subject,
                     obs.reason.empty() ? std::string{} : " reason=" + obs.reason);
        if (sink_)
            sink_(obs);
    }

    // os.uptime_report is the one signal emitted on a schedule rather than in
    // response to a report file. Emitting it ONLY at arm would always drop it: the
    // observer arms PRE-network, before the Subscribe stream is up. So emit it
    // interval-gated off the periodic timer instead — last_uptime_emit_ seeded to 0
    // makes the first timer tick (~kRescanSeconds after arm, stream up by then) emit
    // it, then hourly. Reliable post-connect, and still sparse on the wire.
    void maybe_emit_uptime() {
        const std::int64_t now = now_unix();
        if (now - last_uptime_emit_ < kUptimeIntervalSeconds)
            return;
        last_uptime_emit_ = now;
        if (auto up = macos::uptime_observation(boot_unix(), now))
            emit(std::move(*up));
    }

    // Hardware-health poll (battery + SMART). STATE not events: emit only on a
    // transition INTO a bad state, and suppress while it persists (a standing bad
    // battery must not re-fire hourly). Slow cadence — these change over months.
    // On a healthy machine nothing is emitted (correct: no failure, no signal).
    void maybe_poll_iokit() {
        const std::int64_t now = now_unix();
        if (now - last_iokit_poll_ < kIokitIntervalSeconds)
            return;
        last_iokit_poll_ = now;

        const std::string smart = macos::parse_smart_status(capture_command("/usr/sbin/diskutil info disk0"));
        auto smart_obs = macos::smart_observation(smart, "disk0");
        if (smart_obs && !smart_bad_reported_) {
            smart_bad_reported_ = true;
            emit(std::move(*smart_obs));
        } else if (!smart_obs) {
            smart_bad_reported_ = false; // recovered / healthy — re-arm
        }

        const auto batt = macos::parse_battery_health(
            capture_command("/usr/sbin/system_profiler SPPowerDataType 2>/dev/null"));
        auto batt_obs = macos::battery_observation(batt);
        if (batt_obs && !battery_bad_reported_) {
            battery_bad_reported_ = true;
            emit(std::move(*batt_obs));
        } else if (!batt_obs) {
            battery_bad_reported_ = false;
        }
    }

    // Resource-pressure poll (disk / thermal / memory) on a faster cadence than
    // battery/SMART — these fluctuate. Same poll-and-diff latch discipline: emit on
    // the transition into a bad state, suppress while it persists, re-arm on
    // recovery. The commands are sub-second. Healthy machine → nothing emitted.
    void maybe_poll_resources() {
        const std::int64_t now = now_unix();
        if (now - last_resource_poll_ < kResourceIntervalSeconds)
            return;
        last_resource_poll_ = now;

        // Disk: the writable Data volume (the read-only system volume reads ~full
        // by design and would mislead).
        const auto disk =
            macos::parse_disk_usage(capture_command("/bin/df -k /System/Volumes/Data"));
        auto disk_obs = macos::disk_observation(disk, "Macintosh HD");
        if (disk_obs && !disk_low_reported_) {
            disk_low_reported_ = true;
            emit(std::move(*disk_obs));
        } else if (!disk_obs) {
            disk_low_reported_ = false;
        }

        auto therm_obs =
            macos::thermal_observation(capture_command("/usr/bin/pmset -g therm 2>/dev/null"));
        if (therm_obs && !thermal_reported_) {
            thermal_reported_ = true;
            emit(std::move(*therm_obs));
        } else if (!therm_obs) {
            thermal_reported_ = false;
        }

        auto mem_obs = macos::memory_pressure_observation(
            capture_command("/usr/bin/memory_pressure -Q 2>/dev/null"));
        if (mem_obs && !mem_pressure_reported_) {
            mem_pressure_reported_ = true;
            emit(std::move(*mem_obs));
        } else if (!mem_obs) {
            mem_pressure_reported_ = false;
        }
    }

    void process_new_reports() {
        for (const auto& dir : dirs_) {
            for (const auto& f : list_reports(dir)) {
                const std::string full = dir + "/" + f;
                if (seen_.count(full))
                    continue;
                const std::string content = read_file(full);
                if (content.empty()) {
                    // Not yet readable (a mid-write file, or a permission gap). Leave it
                    // UNSEEN so the next rescan retries — but bound the retries so a
                    // genuinely unreadable file can't loop forever.
                    if (++retry_[full] >= kMaxReadRetries)
                        seen_.insert(full);
                    continue;
                }
                std::optional<SignalObservation> obs;
                if (ends_with(f, ".ips"))
                    obs = macos::parse_ips_report(content);
                else if (ends_with(f, ".diag"))
                    obs = macos::parse_diag_report(content);
                if (obs)
                    emit(std::move(*obs));
                seen_.insert(full); // parsed (or recognised-but-uninteresting) — done
                retry_.erase(full);
            }
        }
    }

    // Poll the unified log for everything new since the checkpoint. Spawns
    // `log show --start <checkpoint> --predicate <p> --style ndjson` (one bounded
    // child per poll — NOT a persistent `log stream`, NOT the ObjC OSLogStore
    // framework), reads it line-by-line, and emits each catalogued event. logd
    // filters server-side via the predicate, so the agent never sees the firehose.
    // `--start` is inclusive, so the boundary second can recur between polls — we
    // dedup it with the set of lines seen at exactly the checkpoint second.
    // Runs on the worker thread only (timer-gated). The popen() still forks, so
    // it takes the process-global fork lock via open_pipe() to avoid the
    // cross-thread BR-001 race with a concurrent run_bounded_subprocess launcher
    // (timer-gating only rules out a race WITHIN this thread). Predicate +
    // checkpoint are internally generated (no injection).
    void poll_oslog() {
        if (oslog_checkpoint_.empty())
            return;
        const std::string cmd = "/usr/bin/log show --start '" + oslog_checkpoint_ +
                                "' --predicate '" + macos::oslog_predicate() +
                                "' --style ndjson 2>/dev/null";
        // B1: RAII — emit() (an arbitrary sink callback) runs inside this read
        // loop, so a throw there must still pclose and must not escape the worker
        // thread (run() also wraps a top-level catch).
        PipeHandle pipe = open_pipe(cmd);
        if (!pipe) {
            spdlog::warn("dex_observer(macos): popen(log show) failed — unified-log poll skipped");
            return;
        }
        std::string newest_ts = oslog_checkpoint_;
        std::unordered_set<std::string> seen_at_newest;
        std::string acc;
        char buf[16384];
        while (std::fgets(buf, sizeof(buf), pipe.get())) {
            acc += buf;
            if (acc.empty() || acc.back() != '\n')
                continue; // a long line split across reads — keep accumulating
            std::string line = std::move(acc);
            acc.clear();
            while (!line.empty() && (line.back() == '\n' || line.back() == '\r'))
                line.pop_back();
            const std::string ts = oslog_line_timestamp(line);
            if (ts.empty())
                continue; // not a log-event line (ndjson preamble / blank)
            // Dedup the inclusive `--start` boundary: a line at exactly the previous
            // checkpoint second that we already emitted last poll.
            if (ts == oslog_checkpoint_ && oslog_seen_at_checkpoint_.count(line))
                continue;
            if (auto obs = macos::parse_oslog_event(line))
                emit(std::move(*obs));
            // Track the newest second + the lines at it for next poll's dedup
            // (log show emits chronologically, so ts is non-decreasing).
            if (ts > newest_ts) {
                newest_ts = ts;
                seen_at_newest.clear();
            }
            if (ts == newest_ts)
                seen_at_newest.insert(std::move(line));
        }
        // pclose runs via PipeHandle dtor at scope end. Advancing the checkpoint
        // only after a clean read means a throw mid-loop re-polls the same window
        // next tick (no lost events).
        oslog_checkpoint_ = std::move(newest_ts);
        oslog_seen_at_checkpoint_ = std::move(seen_at_newest);
    }

    void run() {
        // B1: a single top-level catch so NO exception from a poll, a parser, or a
        // sink callback can escape the worker thread (which would be std::terminate
        // and kill the whole agent process — the Windows engine catches in its OS
        // callback; this thread must do the same). On a caught throw we flip the
        // runtime-health flag and stop collecting rather than crash the agent.
        try {
            run_loop();
        } catch (const std::exception& e) {
            spdlog::error("dex_observer(macos): worker thread caught exception ({}) — collection "
                          "stopping (agent stays up)",
                          e.what());
            if (on_error_)
                on_error_();
        } catch (...) {
            spdlog::error("dex_observer(macos): worker thread caught unknown exception — collection "
                          "stopping (agent stays up)");
            if (on_error_)
                on_error_();
        }
    }

    void run_loop() {
        for (;;) {
            struct kevent ev{};
            const int n = ::kevent(kq_, nullptr, 0, &ev, 1, nullptr);
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                spdlog::warn("dex_observer(macos): kevent() error (errno={}) — collection stopping",
                             errno);
                if (on_error_)
                    on_error_(); // flip the agent's runtime-health flag (UP-1 analogue)
                return;
            }
            if (n == 0)
                continue;
            if (ev.filter == EVFILT_USER && ev.ident == kStopIdent)
                return; // stop() requested
            {
                std::lock_guard lk(mu_);
                if (!running_)
                    return;
            }
            const bool is_timer = (ev.filter == EVFILT_TIMER);
            maybe_emit_uptime();   // interval-gated scalar (first emit ~kRescanSeconds in)
            process_new_reports(); // vnode change or periodic timer
            if (is_timer) {
                poll_oslog();          // unified-log poll (bounded ~0.7s popen)
                maybe_poll_iokit();    // battery/SMART poll (interval-gated, hourly)
                maybe_poll_resources(); // disk/thermal/memory poll (interval-gated, 10 min)
            }
        }
    }

    std::mutex mu_;
    bool running_ = false;
    SignalSink sink_;                // touched only by run(); guarded for setup/teardown
    std::function<void()> on_error_; // runtime-error handler
    std::vector<std::string> dirs_;
    std::vector<int> dir_fds_;
    int kq_ = -1;
    std::unordered_set<std::string> seen_;       // report paths already processed
    std::unordered_map<std::string, int> retry_; // bounded read-retry counters
    std::unordered_map<std::string, RateBucket> rate_;
    std::int64_t last_uptime_emit_ = 0;                       // 0 = never; first timer tick emits
    std::string oslog_checkpoint_;                            // local-time "YYYY-MM-DD HH:MM:SS"
    std::unordered_set<std::string> oslog_seen_at_checkpoint_; // boundary-second dedup
    std::int64_t last_iokit_poll_ = 0;                        // 0 = never; first timer tick polls
    bool smart_bad_reported_ = false;                         // SMART/battery poll-and-diff latches
    bool battery_bad_reported_ = false;
    std::int64_t last_resource_poll_ = 0;                     // disk/thermal/memory cadence
    bool disk_low_reported_ = false;                          // resource poll-and-diff latches
    bool thermal_reported_ = false;
    bool mem_pressure_reported_ = false;
    std::thread thread_;
    int armed_ = 0;
};

} // namespace

// Defined here (not in dex_observer.cpp) so the kqueue/sysctl mechanism stays out
// of the Windows engine TU. The factory in dex_observer.cpp calls this under
// __APPLE__.
std::unique_ptr<ISignalObserver> make_macos_dex_observer() {
    return std::make_unique<MacosDexObserver>();
}

} // namespace yuzu::agent

#endif // __APPLE__
