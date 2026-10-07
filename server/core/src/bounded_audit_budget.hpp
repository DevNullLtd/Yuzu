#pragma once

/// @file bounded_audit_budget.hpp
/// A small KEYED fixed-window row budget for audit rows written on a DENIAL path.
///
/// WHY IT EXISTS. A refusal that writes one audit row per refused call lets an
/// unauthenticated caller turn its own refusals into unbounded audit-store
/// writes. The budget bounds the ROWS, never the refusal: the caller refuses
/// first and unconditionally, then asks `try_admit(key)` only whether it may also
/// write a row. A refused row must never change the outcome of the call it was
/// asked about. The unsampled metric stays the complete count, so suppressed rows
/// are still visible as a counter.
///
/// WHY IT IS KEYED. One budget for everything would let a flood of one kind of
/// denial (one peer, or one reason) use up the window and hide a distinct source's
/// row, such as another certificate-holding peer that is being refused for a reason
/// worth investigating. Each KEY gets its own `max_rows` per window; the caller
/// chooses keys that separate sources it must be able to tell apart (the gateway
/// guard uses `<reason>|<first 8 hex of the peer key>`, and writes a row only for a
/// peer whose key it can compute). A source is protected from another's flood only
/// while at most `max_keys` distinct keys are active in a window; beyond that, new
/// keys share an OVERFLOW bucket (below).
///
/// MEMORY IS BOUNDED. At most `max_keys` distinct keys are tracked per window. A key
/// beyond that is charged to an OVERFLOW bucket chosen by the caller (`overflow_key`;
/// the gateway guard passes `<reason>|*`, so a flood of new keys for one reason spends
/// that reason's overflow rows and cannot starve another reason's). Buckets are
/// themselves bounded: at most `max_keys` named ones, then one shared fallback bucket
/// (also the bucket for a call that names none). A caller minting unlimited distinct
/// keys therefore cannot grow the table and cannot starve the keys already tracked. A key
/// is truncated to `kAuditMaxKeyBytes` before use. The table is emptied whenever a window
/// closes.
///
/// SHAPE. Fixed window, not a token bucket: at most `max_rows` admissions per key
/// in any one window of `window_ms`, the window restarting at the first admission
/// after it elapses. A fixed window can admit up to `2 * max_rows` per key across
/// a window boundary; that is accepted for a bound on writes, not a rate guarantee.
///
/// WINDOW REPORT. The call that opens a new window returns, in
/// `AdmitResult::closed_window_suppressed`, how many rows the CLOSED window refused
/// (0 when none, and 0 for every other call), so the caller can emit one aggregate
/// line per window without a thread or a timer. Consequence: a window that ends
/// the burst is reported when the NEXT denial arrives, not at its own end.
///
/// The clock is injectable (milliseconds on any monotonic scale) so tests need
/// no sleeps. A clock that moves backwards is treated as "inside the current
/// window", so it can never re-open a spent window.
///
/// Thread-safe. The constants are defaults for a denial path on a control-plane
/// RPC; copy the shape, not necessarily the numbers, for a different surface.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>

namespace yuzu::server {

/// Default rows admitted per key per window.
inline constexpr std::size_t kDefaultAuditMaxRows = 10;
/// Default window length in milliseconds.
inline constexpr std::int64_t kDefaultAuditWindowMs = 10'000;
/// Default bound on distinct live keys per window.
inline constexpr std::size_t kDefaultAuditMaxKeys = 64;
/// A key longer than this is truncated before use.
inline constexpr std::size_t kAuditMaxKeyBytes = 96;

class DenialAuditBudget {
public:
    /// Milliseconds on a monotonic scale. Null selects steady_clock.
    using NowMsFn = std::function<std::int64_t()>;

    struct AdmitResult {
        bool admitted{false};
        /// Rows refused during the window this call CLOSED; non-zero only on the call
        /// that opens the next window.
        std::uint64_t closed_window_suppressed{0};
    };

    explicit DenialAuditBudget(std::size_t max_rows = kDefaultAuditMaxRows,
                               std::int64_t window_ms = kDefaultAuditWindowMs, NowMsFn now = {},
                               std::size_t max_keys = kDefaultAuditMaxKeys)
        : max_rows_(max_rows), window_ms_(window_ms > 0 ? window_ms : 1), max_keys_(max_keys),
          now_(now ? std::move(now) : NowMsFn{&steady_now_ms}) {}

    DenialAuditBudget(const DenialAuditBudget&) = delete;
    DenialAuditBudget& operator=(const DenialAuditBudget&) = delete;

    /// `admitted` is true when the caller may write one audit row for `key` now, and
    /// counts that row against the key's budget. `max_rows == 0` never admits.
    [[nodiscard]] AdmitResult try_admit(std::string_view key, std::string_view overflow_key = {}) {
        const std::int64_t now = now_();
        if (key.size() > kAuditMaxKeyBytes)
            key = key.substr(0, kAuditMaxKeyBytes);
        if (overflow_key.size() > kAuditMaxKeyBytes)
            overflow_key = overflow_key.substr(0, kAuditMaxKeyBytes);
        std::lock_guard lk(mu_);
        AdmitResult result;
        if (!window_open_ || now >= window_start_ms_ + window_ms_) {
            result.closed_window_suppressed = suppressed_in_window_;
            window_open_ = true;
            window_start_ms_ = now;
            used_.clear();
            overflow_.clear();
            suppressed_in_window_ = 0;
        }
        std::size_t* slot = nullptr;
        if (const auto it = used_.find(key); it != used_.end()) {
            slot = &it->second;
        } else if (used_.size() < max_keys_) {
            slot = &used_.emplace(std::string{key}, 0).first->second;
        } else {
            // Named overflow buckets are bounded by `max_keys_`; past that, and for a call that
            // names none, the one shared fallback bucket (the empty name) is used.
            auto ov = overflow_.find(overflow_key);
            if (ov == overflow_.end()) {
                const bool may_create = overflow_key.empty() || overflow_.size() < max_keys_;
                ov = overflow_.emplace(std::string{may_create ? overflow_key : std::string_view{}}, 0)
                         .first;
            }
            slot = &ov->second;
        }
        if (*slot >= max_rows_) {
            ++suppressed_total_;
            ++suppressed_in_window_;
            return result; // admitted == false
        }
        ++*slot;
        result.admitted = true;
        return result;
    }

    /// Rows refused by the budget since construction.
    [[nodiscard]] std::uint64_t suppressed_total() const {
        std::lock_guard lk(mu_);
        return suppressed_total_;
    }

    /// Keys tracked in the current window plus the overflow buckets that have been used. At most
    /// `2 * max_keys + 1`.
    [[nodiscard]] std::size_t live_keys() const {
        std::lock_guard lk(mu_);
        return used_.size() + overflow_.size();
    }

private:
    static std::int64_t steady_now_ms() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now().time_since_epoch())
            .count();
    }

    const std::size_t max_rows_;
    const std::int64_t window_ms_;
    const std::size_t max_keys_;
    const NowMsFn now_;
    mutable std::mutex mu_;
    bool window_open_{false};
    std::int64_t window_start_ms_{0};
    std::map<std::string, std::size_t, std::less<>> used_; ///< key -> rows used this window
    std::map<std::string, std::size_t, std::less<>> overflow_; ///< overflow bucket -> rows used
    std::uint64_t suppressed_total_{0};
    std::uint64_t suppressed_in_window_{0};
};

} // namespace yuzu::server
