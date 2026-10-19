#pragma once

/// @file crypto_shared_read.hpp
/// Single-flight sharing of one `/crypto` read (the unfiltered, unconfined library summary,
/// owned by `LocalCryptoApi`). Header-only so the unit tests can drive its semantics without a
/// database (L5). Pure header (no store, wire or I/O types); core-side by use.

#include <atomic>
#include <chrono>
#include <cstddef>
#include <exception>
#include <expected>
#include <future>
#include <mutex>
#include <utility>

namespace yuzu::server {

/// One shared read in flight, reused for `ttl` once it SUCCEEDED (a failure is never reused:
/// the next caller after it reads again). Concurrent callers wait on the read in flight instead
/// of each taking an admission slot; a waiter gives up after `wait` and answers `busy`. The
/// computing caller always settles the shared state (value or exception), so a waiter never
/// hangs on an abandoned read: a compute that THROWS rethrows to its own caller, every waiter
/// on it answers `failed`, and the next call reads again.
template <class V, class E> class SharedRead {
public:
    using Result = std::expected<V, E>;

    SharedRead(E busy, E failed, std::chrono::steady_clock::duration wait = std::chrono::seconds(15))
        : busy_(std::move(busy)), failed_(std::move(failed)), wait_(wait) {}

    template <class F> Result get(std::chrono::steady_clock::duration ttl, F&& compute) {
        std::shared_future<Result> fut;
        std::promise<Result> mine;
        {
            std::lock_guard lock(mu_);
            const auto now = std::chrono::steady_clock::now();
            const bool in_flight =
                fut_.valid() &&
                fut_.wait_for(std::chrono::seconds(0)) != std::future_status::ready;
            bool fresh_ok = false;
            if (fut_.valid() && !in_flight && now - started_ < ttl) {
                try {
                    fresh_ok = fut_.get().has_value();
                } catch (...) {
                    fresh_ok = false; // a read that threw is never reused
                }
            }
            if (in_flight || fresh_ok) {
                fut = fut_;
                if (in_flight)
                    joined_in_flight_.fetch_add(1, std::memory_order_release);
            } else {
                fut_ = mine.get_future().share();
                started_ = now;
            }
        }
        if (fut.valid()) {
            if (fut.wait_for(wait_) != std::future_status::ready)
                return std::unexpected(busy_);
            try {
                return fut.get();
            } catch (...) {
                return std::unexpected(failed_);
            }
        }
        try {
            Result r = compute();
            mine.set_value(r);
            return r;
        } catch (...) {
            mine.set_exception(std::current_exception());
            throw;
        }
    }

    /// TEST HOOK: how many callers have joined a read still in flight (counted under the lock,
    /// before they wait on it), so a test can latch on "the waiter is now waiting on THIS
    /// compute" instead of sleeping. Monotonic; no production reader.
    std::size_t joined_in_flight_for_test() const noexcept {
        return joined_in_flight_.load(std::memory_order_acquire);
    }

private:
    const E busy_;
    const E failed_;
    const std::chrono::steady_clock::duration wait_;
    std::mutex mu_;
    std::shared_future<Result> fut_;
    std::chrono::steady_clock::time_point started_{};
    std::atomic<std::size_t> joined_in_flight_{0};
};

} // namespace yuzu::server
