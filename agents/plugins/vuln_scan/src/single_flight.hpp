#pragma once

/**
 * single_flight.hpp — process-wide single flight with a short result cache (portable, header-only).
 *
 * One caller (the leader) runs `run`; concurrent callers wait for its result instead of starting a
 * second run; a fresh result (success OR failure) is reused for `ttl`. It never wedges:
 *   - the leader's "running" flag is cleared by a scope guard on EVERY exit, including an exception
 *     thrown by `run`, by the result copy, or by the mutex itself (the flag is atomic, so clearing
 *     it needs no lock);
 *   - a waiter waits at most `wait_cap`, then returns `failed` (an unreadable result) rather than
 *     blocking forever;
 *   - the cache write is best-effort (a bad_alloc while copying only skips the cache).
 * There is deliberately no "steal the flight" path: a stampede of stealing waiters would run the
 * tool once per waiter.
 */

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>

namespace yuzu::vuln {

template <class R>
class SingleFlight {
public:
    using clock = std::chrono::steady_clock;

    template <class Run>
    R get(Run&& run, std::chrono::milliseconds ttl, std::chrono::milliseconds wait_cap,
          const R& failed) {
        const auto start = clock::now();
        std::unique_lock lk(mu_);
        for (;;) {
            if (have_ && clock::now() - at_ < ttl)
                return result_;
            if (!running_.load())
                break;
            if (cv_.wait_until(lk, start + wait_cap) == std::cv_status::timeout && running_.load())
                return failed; // the leader is overdue: report unreadable, never block forever
        }
        running_.store(true);
        lk.unlock();

        struct Done {
            SingleFlight* f;
            ~Done() {
                f->running_.store(false); // lock-free: cannot throw
                try {
                    f->cv_.notify_all();
                } catch (...) {
                }
            }
        } done{this};

        R r = failed;
        try {
            r = run();
        } catch (...) {
            // leave r as the failed result
        }
        try {
            std::lock_guard g(mu_);
            result_ = r;
            at_ = clock::now();
            have_ = true;
        } catch (...) {
            // best effort: no cache this time
        }
        return r;
    }

private:
    std::mutex mu_;
    std::condition_variable cv_;
    std::atomic<bool> running_{false};
    bool have_ = false;
    clock::time_point at_{};
    R result_{};
};

} // namespace yuzu::vuln
