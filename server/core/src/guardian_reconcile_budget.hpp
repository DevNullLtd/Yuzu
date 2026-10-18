#pragma once

/// @file guardian_reconcile_budget.hpp
/// Admission budget for the Guardian heartbeat reconcile push (#5513).
///
/// WHY IT EXISTS. The reconcile path runs on the heartbeat thread of every agent that
/// reports a policy generation behind the server's. At fleet scale a policy bump (or a
/// fleet-wide restart) makes a large share of heartbeats eligible at once, and each
/// push costs store reads, a registry lock hold and a gRPC/gateway write. Admission is
/// bounded by MEASURED COST, not by a guessed rate: a leaky bucket denominated in
/// milliseconds of reconcile wall time per wall second. At a high per-push cost it
/// admits few pushes per second, and when the cost falls it admits more, with no
/// retuning. A count ceiling per one-second window bounds the burst a still-full
/// bucket would otherwise allow while no push has finished (and so debited) yet.
///
/// CONTRACT.
///   - `try_admit()` answers "may this reconcile run now?". false means SHED: the caller
///     returns without touching the per-agent claim, so the agent simply re-reports a
///     stale generation on its next heartbeat. It admits only when the balance is
///     strictly positive AND fewer than `max_per_s` admissions happened in the current
///     one-second window. It does NOT debit.
///   - `debit(measured)` charges the wall time of an admitted push. The balance may go
///     negative, so one slow push makes later admissions shed until the bucket has
///     refilled. A shed never debits and never counts toward the window ceiling.
///   - Refill is `budget_ms_per_s` per elapsed wall second, up to `burst_ms`.
///   - Admissions that overlap (several `try_admit()` before any `debit()`) are all
///     charged only when each push finishes; the count ceiling is what bounds that
///     overlap. This is a deliberate trade for a budget that follows measured cost.
///   - The balance is floored at `-kMaxDebtSeconds * budget_ms_per_s` so that one
///     pathologically long push cannot shed the replica for an unbounded time. The floor
///     is a recovery bound: a push longer than that repays only the floor.
///   - Per replica, in memory. It protects per-replica resources (registry lock, pool,
///     threads); store load is the budget times the number of replicas.
///
/// CONFIG VALIDATION. A value below the documented minimum (which includes zero,
/// negatives and -inf) or NaN is clamped to that minimum (`kMinBudgetMsPerS`,
/// `kMinBurstMs`, `kMinMaxPerS`); a value above the documented maximum (including +inf)
/// is clamped to it. Nothing divides by a configured value.
/// `config()` returns the values actually in force.
///
/// CLOCK INJECTION. The clock is a `std::function<std::chrono::steady_clock::time_point()>`;
/// null selects the real steady clock. Tests drive a manual clock and never sleep. A
/// clock that moves backwards is treated as no time elapsed (no negative refill, no
/// re-opened window). The clock is called under the internal mutex and must not call
/// back into this object.
///
/// Thread-safe: one internal mutex; the two counters are atomics so the metric reader
/// never takes the lock.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <functional>
#include <locale>
#include <mutex>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::server {

/// Budget configuration (namespace scope so it can be a default argument; see the
/// class comment for clamping). The defaults here are provisional starting values, not
/// derived from fleet measurement. The server does not use them: `ServerImpl` builds the
/// budget from `--guardian-reconcile-budget-ms-per-s`, `--guardian-reconcile-burst-ms` and
/// `--guardian-reconcile-max-per-s` (server_guardian_reconcile_options.hpp), whose own
/// defaults are likewise provisional.
struct GuardianReconcileBudgetConfig {
    /// Reconcile-milliseconds replenished per wall second.
    double budget_ms_per_s{100.0};
    /// Bucket capacity in reconcile-milliseconds; the bucket starts full.
    double burst_ms{200.0};
    /// Admissions allowed per one-second window.
    std::uint32_t max_per_s{200};
};

class GuardianReconcileBudget {
public:
    using Clock = std::chrono::steady_clock;
    /// Null selects `steady_clock::now`.
    using ClockFn = std::function<Clock::time_point()>;

    /// Documented clamp bounds (see CONFIG VALIDATION above).
    static constexpr double kMinBudgetMsPerS = 1.0;
    static constexpr double kMaxBudgetMsPerS = 1'000.0 * 1'000.0;  // 1000 s of work per second
    static constexpr double kMinBurstMs = 1.0;
    static constexpr double kMaxBurstMs = 3'600.0 * 1'000.0;  // one hour
    static constexpr std::uint32_t kMinMaxPerS = 1;
    static constexpr std::uint32_t kMaxMaxPerS = 1'000'000;
    /// The balance never goes below `-kMaxDebtSeconds * budget_ms_per_s`.
    static constexpr double kMaxDebtSeconds = 30.0;

    using Config = GuardianReconcileBudgetConfig;

    explicit GuardianReconcileBudget(Config cfg = {}, ClockFn clock = {})
        : cfg_(sanitize(cfg)), clock_(clock ? std::move(clock) : ClockFn{[] { return Clock::now(); }}),
          balance_ms_(cfg_.burst_ms), last_refill_(clock_()), window_start_(last_refill_) {}

    GuardianReconcileBudget(const GuardianReconcileBudget&) = delete;
    GuardianReconcileBudget& operator=(const GuardianReconcileBudget&) = delete;

    /// true = admit this reconcile; false = SHED (counted, no state change otherwise).
    [[nodiscard]] bool try_admit() {
        std::lock_guard lk(mu_);
        const auto now = clock_();
        refill_locked(now);
        if (now >= window_start_ + std::chrono::seconds(1)) {
            window_start_ = now;
            window_count_ = 0;
        }
        if (balance_ms_ > 0.0 && window_count_ < cfg_.max_per_s) {
            ++window_count_;
            admitted_.fetch_add(1, std::memory_order_relaxed);
            return true;
        }
        shed_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    /// Charge the measured wall time of an admitted push. Negative durations are ignored.
    void debit(std::chrono::nanoseconds measured) {
        if (measured.count() <= 0)
            return;
        const double ms = std::chrono::duration<double, std::milli>(measured).count();
        std::lock_guard lk(mu_);
        refill_locked(clock_());
        balance_ms_ = std::max(balance_ms_ - ms, -kMaxDebtSeconds * cfg_.budget_ms_per_s);
    }

    [[nodiscard]] std::uint64_t admitted_total() const {
        return admitted_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t shed_total() const {
        return shed_.load(std::memory_order_relaxed);
    }

    /// The configuration in force after clamping.
    [[nodiscard]] Config config() const { return cfg_; }

    /// Current balance after applying any refill due at the injected clock. For gauges
    /// and tests; may be negative.
    [[nodiscard]] double balance_ms() {
        std::lock_guard lk(mu_);
        refill_locked(clock_());
        return balance_ms_;
    }

private:
    static double clamp_double(double v, double lo, double hi) {
        if (std::isnan(v) || v < lo)  // NaN and -inf land on the minimum
            return lo;
        return v > hi ? hi : v;  // +inf lands on the maximum
    }

    static Config sanitize(Config c) {
        c.budget_ms_per_s = clamp_double(c.budget_ms_per_s, kMinBudgetMsPerS, kMaxBudgetMsPerS);
        c.burst_ms = clamp_double(c.burst_ms, kMinBurstMs, kMaxBurstMs);
        c.max_per_s = std::clamp(c.max_per_s, kMinMaxPerS, kMaxMaxPerS);
        return c;
    }

    // Caller holds mu_. A non-advancing clock adds nothing.
    void refill_locked(Clock::time_point now) {
        if (now <= last_refill_)
            return;
        const double elapsed_s = std::chrono::duration<double>(now - last_refill_).count();
        last_refill_ = now;
        balance_ms_ = std::min(cfg_.burst_ms, balance_ms_ + elapsed_s * cfg_.budget_ms_per_s);
    }

    const Config cfg_;
    const ClockFn clock_;
    std::mutex mu_;
    double balance_ms_;
    Clock::time_point last_refill_;
    Clock::time_point window_start_;
    std::uint32_t window_count_{0};
    std::atomic<std::uint64_t> admitted_{0};
    std::atomic<std::uint64_t> shed_{0};
};

/// One warning line per admission flag whose value the budget clamped, comparing what the
/// operator configured (`requested`) with what the budget enforces (`effective`, from
/// `GuardianReconcileBudget::config()`). Empty when nothing was clamped. A NaN request always
/// differs from its clamped value, so it is reported too. The server logs each line at warn
/// level at start-up, and the wording is pinned by test_guardian_reconcile_budget.cpp.
[[nodiscard]] inline std::vector<std::string> guardian_reconcile_clamp_warnings(
    const GuardianReconcileBudgetConfig& requested, const GuardianReconcileBudgetConfig& effective) {
    const auto render = [](auto v) {
        std::ostringstream os;
        os.imbue(std::locale::classic());
        os << v;
        return os.str();
    };
    const auto line = [&](const char* flag, const std::string& was, const std::string& now) {
        return std::string("Guardian reconcile admission: ") + flag + " " + was +
               " was outside the supported range and was clamped to " + now;
    };
    std::vector<std::string> out;
    if (effective.budget_ms_per_s != requested.budget_ms_per_s)
        out.push_back(line("--guardian-reconcile-budget-ms-per-s",
                           render(requested.budget_ms_per_s), render(effective.budget_ms_per_s)));
    if (effective.burst_ms != requested.burst_ms)
        out.push_back(line("--guardian-reconcile-burst-ms", render(requested.burst_ms),
                           render(effective.burst_ms)));
    if (effective.max_per_s != requested.max_per_s)
        out.push_back(line("--guardian-reconcile-max-per-s", render(requested.max_per_s),
                           render(effective.max_per_s)));
    return out;
}

}  // namespace yuzu::server
