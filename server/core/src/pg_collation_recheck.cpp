#include "pg_collation_recheck.hpp"

#include "background_jobs.hpp"

#include <yuzu/metrics.hpp>

#include <algorithm>
#include <utility>

namespace yuzu::server {

PgCollationRecheck::PgCollationRecheck(CheckFn check, yuzu::MetricsRegistry* metrics,
                                       std::chrono::milliseconds interval,
                                       pg::CollationState initial,
                                       std::chrono::milliseconds unsettled_interval)
    : check_(std::move(check)), metrics_(metrics), interval_(interval),
      unsettled_interval_(unsettled_interval), state_(initial) {}

PgCollationRecheck::~PgCollationRecheck() {
    stop();
}

pg::CollationState PgCollationRecheck::state() const {
    std::lock_guard<std::mutex> lk(state_mu_);
    return state_;
}

void PgCollationRecheck::tick() noexcept {
    if (stop_.load(std::memory_order_acquire) || !check_)
        return;
    pg::CollationReport report;
    try {
        report = check_();
    } catch (...) {
        report.verdict = pg::CollationVerdict::Unreadable;
        // Best effort: assigning the text can throw (out of memory) and this function is noexcept.
        try {
            report.failure = "the collation check threw";
        } catch (...) {
        }
    }
    // A check cut short by stop() is not reported: the server is going down.
    if (stop_.load(std::memory_order_acquire))
        return;
    try {
        std::lock_guard<std::mutex> lk(state_mu_);
        pg::report_collation_check(report, metrics_, state_);
    } catch (...) {
        // report_collation_check does not throw; this only guards the lock.
    }
    ticks_.fetch_add(1, std::memory_order_release);
}

void PgCollationRecheck::start() {
    std::lock_guard<std::mutex> lk(mu_);
    if (started_ || stop_.load(std::memory_order_acquire))
        return;
    thread_ = std::thread([this] { run_loop(); }); // may throw (thread exhaustion): started_ stays false
    started_ = true;
}

void PgCollationRecheck::request_stop() noexcept {
    {
        // Under mu_ so the loop cannot test its wait predicate, find it false and block after
        // this notify has gone by (a lost wakeup).
        std::lock_guard<std::mutex> lk(mu_);
        stop_.store(true, std::memory_order_release);
    }
    cv_.notify_all();
}

void PgCollationRecheck::stop() {
    request_stop();
    // Join outside mu_: the loop takes mu_ for its interval wait.
    if (thread_.joinable() && thread_.get_id() != std::this_thread::get_id())
        thread_.join();
}

std::chrono::milliseconds PgCollationRecheck::next_wait() const {
    // Fast while the picture is unsettled: a standing Mismatch (the gauge must follow a repair
    // within a minute, not an hour), no conclusive verdict yet (the start-time check was
    // unreadable), or the latest check unreadable. Hourly only when the latest conclusive verdict
    // is Ok or NotApplicable and the checks since have been readable.
    bool unsettled = false;
    {
        std::lock_guard<std::mutex> lk(state_mu_);
        unsettled = state_.last == pg::CollationLast::Mismatch ||
                    state_.last == pg::CollationLast::None || state_.unreadable;
    }
    return unsettled ? std::min(interval_, unsettled_interval_) : interval_;
}

void PgCollationRecheck::run_loop() {
    YUZU_ASSERT_BACKGROUND_JOB("pg_collation_recheck.tick"); // WS-10 ReplicaSafe (per-replica)
    for (;;) {
        // The wait is chosen from the state the previous report left (state_mu_ is a leaf, taken
        // and released before mu_).
        const auto wait = next_wait();
        {
            std::unique_lock<std::mutex> lk(mu_);
            cv_.wait_for(lk, wait, [this] { return stop_.load(std::memory_order_acquire); });
            if (stop_.load(std::memory_order_acquire))
                return;
        }
        tick(); // noexcept
    }
}

} // namespace yuzu::server
