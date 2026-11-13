#pragma once

/// @file pg_collation_recheck.hpp
/// The repeat of the PostgreSQL collation version check (`pg/pg_collation_check.hpp`): hourly
/// while the picture is settled, every minute while it is not.
///
/// WHY. The check at start cannot see drift that appears while the server keeps running (a
/// managed-PostgreSQL maintenance event that changes the host library), and a gauge set once never
/// clears after the database is fixed. This loop repeats the check, so the gauge follows the
/// database without a restart.
///
/// SHAPE. A small class that owns one thread (`std::thread`, not `std::jthread`: not every
/// supported toolchain has it), a stop flag and a condition variable, and takes the check as an
/// injected function, so tests drive `tick()` directly and run the loop with a tiny interval. It
/// mirrors `PgReachabilityProbe` with one deliberate difference: that probe ticks first and then
/// waits, this loop WAITS first and then ticks. The start-time check stays in the ServerImpl
/// constructor (it is what makes a mismatch visible before any store serves); the first recheck is
/// one interval after `start()`, so the counter does not count the start twice.
///
/// WHAT A TICK DOES. It runs the injected check (in production
/// `pg::check_collation_version(pool)`, one short transaction on a pooled connection with its own
/// bounds) and hands the report to `pg::report_collation_check`, which owns the state machine: the
/// gauge follows the latest conclusive verdict, an unreadable check leaves it alone, and the log
/// speaks only on a transition. The state is seeded from the constructor-time check, so a
/// standing mismatch is not logged a second time at the first recheck. A tick never throws.
///
/// CLASSIFICATION. `pg_collation_recheck.tick` in `background_jobs.hpp`: ReplicaSafe, per replica.
/// It is read-only and every replica exports its own gauge, so it is never leader-gated.
///
/// LIFETIME (ServerImpl). `start()` runs in `run()`, after the constructor-time check and past
/// every fail-closed return. `ServerImpl::stop()` calls `request_stop()` EARLY, at the start of
/// the shutdown drain, and `stop()` (signal and join) LATE, immediately before the PostgreSQL pool
/// the check function borrows is reset, after the leader lease is released and the audit and
/// offload flushes have run (a wait there must not be able to skip them). The split exists because
/// the join can wait out the check in flight. With the pool defaults that wait is about 15 seconds
/// (the acquire and each of the two statements are bounded at 5 seconds in
/// `pg_collation_check.hpp`; a saturated pool fails the acquire sooner), and up to about 35 seconds
/// if the network drops packets (a new connection adds the pool's 10 second connect timeout, and a
/// silent connection is given up on by `tcp_user_timeout_ms`, 10 seconds by default, which
/// `statement_timeout` cannot enforce; `pg_pool.hpp`). It is NOT bounded against a backend that is
/// frozen while its connection keeps acknowledging data, a host-name lookup that hangs, or a
/// connection string that sets `tcp_user_timeout` to 0: libpq has no client-side query deadline
/// here. Signalled early, a check in flight runs while the rest of teardown runs, so the final
/// join waits only for whatever is left of it by then. The
/// check itself is not interrupted: `request_stop()` makes the loop exit after it and makes the
/// tick drop its report. A check that has already passed `tick()`'s stop test may still start in
/// the instant before the check function is called; its report is then dropped, and the join
/// keeps the pool alive until it returns. `request_stop()` and `stop()` are idempotent and sticky
/// (no restart).

#include "pg/pg_collation_check.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <thread>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server {

/// How often the check is repeated. A constant: there is deliberately no flag for it.
inline constexpr std::chrono::seconds kCollationRecheckInterval{3600};
/// How often it is repeated while the picture is UNSETTLED: the last conclusive verdict is
/// Mismatch (after a repair the gauge must not outlast it by up to an hour), or there is no
/// conclusive verdict yet (the start-time check was unreadable), or the latest check was
/// unreadable. One cheap read a minute (the same bounded transaction as the hourly one) is the
/// price, paid only while unsettled. The rule is `PgCollationRecheck::next_wait`.
inline constexpr std::chrono::seconds kCollationUnsettledRecheckInterval{60};
static_assert(kCollationUnsettledRecheckInterval < kCollationRecheckInterval,
              "the unsettled cadence must be the faster one");
static_assert(kCollationRecheckInterval == std::chrono::seconds{3600},
              "the hourly recheck interval is part of the documented behaviour (server-admin.md, "
              "metrics.md); a shorter one is a decision, not an edit");

class PgCollationRecheck {
public:
    /// One check. Must not block unbounded and must not throw (a throw is swallowed).
    using CheckFn = std::function<pg::CollationReport()>;

    /// `metrics` may be null and must outlive this object. `initial` is the state left by the
    /// constructor-time report. While the state is unsettled (last conclusive verdict Mismatch or
    /// none yet, or the latest check unreadable) the loop waits `unsettled_interval` instead of
    /// `interval` when that is shorter.
    PgCollationRecheck(CheckFn check, yuzu::MetricsRegistry* metrics,
                       std::chrono::milliseconds interval, pg::CollationState initial = {},
                       std::chrono::milliseconds unsettled_interval =
                           kCollationUnsettledRecheckInterval);
    ~PgCollationRecheck();
    PgCollationRecheck(const PgCollationRecheck&) = delete;
    PgCollationRecheck& operator=(const PgCollationRecheck&) = delete;

    /// One recheck on the calling thread. Does nothing after `stop()`. Never throws. Safe to call
    /// from a test while the loop is not running; the loop is the only caller in production.
    void tick() noexcept;

    /// Spawn the loop. Idempotent; a no-op after `stop()`.
    void start();

    /// Ask the loop to stop WITHOUT joining it: sets the stop flag under the mutex and wakes the
    /// loop. Idempotent, sticky, callable from any thread, including before `start()` (which is
    /// then a no-op). A check in flight is not interrupted; its report is dropped when it returns,
    /// exactly as after `stop()`. The thread is still joined by `stop()`.
    void request_stop() noexcept;

    /// `request_stop()` and then join the loop. Idempotent and sticky; safe before `start()` and
    /// from the destructor. Not safe to call from two threads at once (the join).
    void stop();

    /// Number of reports applied (a check dropped because stop was requested is not counted);
    /// for tests.
    [[nodiscard]] std::uint64_t ticks() const noexcept {
        return ticks_.load(std::memory_order_acquire);
    }

    /// The state after the latest report; for tests.
    [[nodiscard]] pg::CollationState state() const;

private:
    void run_loop();
    [[nodiscard]] std::chrono::milliseconds next_wait() const;

    const CheckFn check_;
    yuzu::MetricsRegistry* const metrics_;
    const std::chrono::milliseconds interval_;
    const std::chrono::milliseconds unsettled_interval_;

    std::atomic<bool> stop_{false};
    std::atomic<std::uint64_t> ticks_{0};
    std::mutex mu_; ///< guards the cv wait and the thread start; the join is done outside it
    std::condition_variable cv_;
    bool started_ = false; // guarded by mu_
    std::thread thread_;

    mutable std::mutex state_mu_; ///< leaf; guards state_ only, never held across the check
    pg::CollationState state_;
};

} // namespace yuzu::server
