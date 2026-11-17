#pragma once

/**
 * echo_open_retry.hpp -- the policy and the one stoppable loop behind "Echo loads offline and
 * retries" (owner ruling 2026-11-16, #7290).
 *
 * When EchoDatabase::open fails on the v10 roll-up step (or lacks the free space for it), the
 * plugin still loads, reports `storage_state|offline|<reason>` and retries the open in the
 * background instead of staying absent until an agent restart. This header holds the pure
 * schedule and deadline functions and the thread that spaces the attempts. Header-only and free
 * of the TU-local EchoPlugin so the unit suite can drive it.
 *
 * Back-off: 1, 5 and 15 minutes, then hourly, for ever (open_retry_delay).
 *
 * Per-attempt migration deadline: 60 s plus 2 s per MiB of database file, doubled once for every
 * earlier attempt that ended on the deadline, capped at one hour (v10_migration_deadline). The
 * one measured migration took 55 s on a 242 MB file, so a short fixed bound would interrupt
 * every attempt on a full-size database and Echo would never come online. The doubling lowers the
 * slowest disk that still migrates; the cap bounds how long the write lock is held per attempt.
 */

#include <spdlog/spdlog.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <exception>
#include <functional>
#include <mutex>
#include <thread>
#include <utility>

namespace yuzu::echo {

/// How long to wait before the next open attempt, given how many attempts have failed so far
/// (the failure of init's own synchronous attempt counts as 1, so the first retry waits 60 s).
[[nodiscard]] constexpr std::chrono::seconds open_retry_delay(unsigned failed_attempts) noexcept {
    switch (failed_attempts) {
    case 0:
    case 1:
        return std::chrono::seconds{60};
    case 2:
        return std::chrono::seconds{300};
    case 3:
        return std::chrono::seconds{900};
    default:
        return std::chrono::seconds{3600};
    }
}

inline constexpr std::chrono::seconds kV10DeadlineCap{3600};

/// The wall-clock bound on one v10 migration attempt over a database file of `file_bytes`.
/// A negative size counts as 0.
[[nodiscard]] constexpr std::chrono::seconds
v10_migration_deadline(std::int64_t file_bytes, unsigned deadline_hits = 0) noexcept {
    const std::int64_t mib = file_bytes > 0 ? file_bytes / (1024 * 1024) : 0;
    std::int64_t secs = 60 + 2 * mib;
    for (unsigned i = 0; i < deadline_hits && secs < kV10DeadlineCap.count(); ++i)
        secs *= 2;
    return std::chrono::seconds{std::min<std::int64_t>(secs, kV10DeadlineCap.count())};
}

/// One background thread that runs `attempt` after each back-off until it reports success or the
/// loop is stopped. `attempt(n, cancelled)` receives the attempt number (init's own try was #1)
/// and a predicate that turns true on stop(); it returns true when the work is done (no further
/// attempt) and false to be retried after the next back-off. An exception from `attempt` is
/// logged and counts as a failed attempt.
///
/// start() and stop() are called from the owning plugin's init/shutdown thread only.
class OpenRetryLoop {
public:
    using Attempt = std::function<bool(unsigned attempt, const std::function<bool()>& cancelled)>;
    using Delay = std::function<std::chrono::milliseconds(unsigned failed_attempts)>;

    OpenRetryLoop() = default;
    OpenRetryLoop(const OpenRetryLoop&) = delete;
    OpenRetryLoop& operator=(const OpenRetryLoop&) = delete;
    ~OpenRetryLoop() { stop(); }

    /// `delay` defaults to open_retry_delay; `initial_failures` is the failed attempts so far.
    void start(Attempt attempt, Delay delay = {}, unsigned initial_failures = 1) {
        stop();
        if (!delay) {
            delay = [](unsigned failed) {
                return std::chrono::duration_cast<std::chrono::milliseconds>(open_retry_delay(failed));
            };
        }
        {
            std::lock_guard lock(mu_);
            stop_ = false;
        }
        thread_ = std::thread([this, attempt = std::move(attempt), delay = std::move(delay),
                               failed = initial_failures]() mutable {
            const std::function<bool()> cancelled = [this] { return stopped(); };
            std::unique_lock lock(mu_);
            while (!stop_) {
                cv_.wait_for(lock, delay(failed), [this] { return stop_.load(); });
                if (stop_)
                    break;
                lock.unlock();
                bool done = false;
                try {
                    done = attempt(failed + 1, cancelled);
                } catch (const std::exception& e) {
                    spdlog::error("ECHO: open retry attempt threw: {}", e.what());
                } catch (...) {
                    spdlog::error("ECHO: open retry attempt threw");
                }
                lock.lock();
                if (done)
                    break;
                ++failed;
            }
        });
    }

    /// Ask the thread to end, wake it, and join it. Idempotent; a running attempt sees
    /// `cancelled()` turn true and is expected to return promptly.
    void stop() noexcept {
        {
            std::lock_guard lock(mu_);
            stop_ = true;
        }
        cv_.notify_all();
        if (thread_.joinable())
            thread_.join();
    }

private:
    // Lock-free: the migration polls it from a SQLite progress handler.
    [[nodiscard]] bool stopped() const noexcept { return stop_.load(); }

    std::mutex mu_;
    std::condition_variable cv_;
    std::atomic<bool> stop_{true}; // written under mu_ so the wait cannot miss it
    std::thread thread_;
};

} // namespace yuzu::echo
