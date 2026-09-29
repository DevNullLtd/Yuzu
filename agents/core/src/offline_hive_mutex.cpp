#include <yuzu/agent/offline_hive_mutex.hpp>

#include <spdlog/spdlog.h>

namespace yuzu::agent {

std::mutex& offline_hive_mutex() {
    static std::mutex m;
    return m;
}

namespace {
// A hold past this length is unusual enough (the offline arm is file-I/O
// bound, not compute-bound) to warrant a warn rather than a debug log --
// see offline_hive_mutex.hpp's INSTRUMENTATION note.
constexpr auto kSlowHoldWarnThreshold = std::chrono::milliseconds(500);
} // namespace

ScopedOfflineHiveLock::ScopedOfflineHiveLock(const char* caller)
    : caller_(caller), lock_(offline_hive_mutex(), std::defer_lock) {
    const auto wait_start = std::chrono::steady_clock::now();
    lock_.lock();
    acquired_at_ = std::chrono::steady_clock::now();
    waited_ = std::chrono::duration_cast<std::chrono::milliseconds>(acquired_at_ - wait_start);
    // No I/O here deliberately -- the wait-time log fires from the
    // destructor instead, alongside the hold-time log, so both happen
    // after unlock() below and logging itself never extends another
    // caller's wait. See the destructor for why that placement matters and
    // why the destructor, not here, is where both log calls' try/catch
    // guards live.
}

ScopedOfflineHiveLock::~ScopedOfflineHiveLock() {
    const auto held = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - acquired_at_);
    lock_.unlock();
    // Diagnostics must never throw out of a destructor -- it's implicitly
    // noexcept, so an escaping exception here would call std::terminate()
    // rather than merely fail to log (this codebase's established idiom
    // for lifetime-boundary logging; see e.g. mcp_stream_bridge.cpp's
    // best-effort spdlog::info, similarly caught-and-discarded). Both log
    // calls sit here, after unlock() above -- not the wait-time one next
    // to lock_.lock() in the constructor -- because logging before
    // releasing would hold the process-wide mutex for the duration of a
    // spdlog call (format + sink I/O), directly extending the wait for
    // whichever of the other four plugins is queued behind it; that
    // coupling is worst precisely when it would fire (under contention,
    // possibly against a degraded sink), so it's the wait-time line
    // arriving slightly late -- at destruction instead of at acquire --
    // rather than risking a pile-up during an active incident
    // (governance Gate 8: sre). Two INDEPENDENT try/catch blocks, not
    // one -- a throw from either log call must never suppress the other,
    // especially not the hold-time warn branch, the higher-value signal
    // of the two (governance Gate 8: unhappy-path, UP-7).
    try {
        if (waited_ > std::chrono::milliseconds::zero())
            spdlog::debug("offline_hive_mutex: {} waited {}ms to acquire", caller_,
                          waited_.count());
    } catch (...) {
    }
    try {
        if (held >= kSlowHoldWarnThreshold)
            spdlog::warn("offline_hive_mutex: {} held lock for {}ms", caller_, held.count());
        else
            spdlog::debug("offline_hive_mutex: {} held lock for {}ms", caller_, held.count());
    } catch (...) {
    }
}

} // namespace yuzu::agent
