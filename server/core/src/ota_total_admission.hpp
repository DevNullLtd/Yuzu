#pragma once

/// @file ota_total_admission.hpp
///
/// The SERVER-WIDE OTA transfer gate (#913's fleet-wide half): the in-flight
/// counter, the two-ceiling reserve arithmetic, and the RAII slot that releases
/// it, as one testable unit.
///
/// WHY IT IS SEPARATE, and this is the whole reason the file exists. While the
/// counter lived inline in the handler, NOTHING OBSERVED IT. Every live-wire
/// case could only reach the gate one call at a time — `max_concurrent_total=0`
/// rejects with the counter untouched (`prev = 0 >= 0`), and a cap of 1 driven
/// sequentially admits with the counter untouched (`prev` is 0 every time) — so
/// deleting the `fetch_add` outright left the entire `[ota]` suite green. A gate
/// whose central mechanism can be removed without a red test is not a tested
/// gate, and a live `DownloadUpdate` cannot be held mid-transfer from a unit
/// test without a package on disk and a peer that stalls.
///
/// So OCCUPANCY is tested here, directly and deterministically: acquire, hold,
/// watch the next acquire refuse, release, watch it admit again. No threads, no
/// timing. `test_ota_download_bound.cpp` still proves the gate is WIRED into the
/// real handler over the real wire; this proves it COUNTS.

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <optional>

namespace yuzu::server::detail {

class OtaTotalAdmission {
  public:
    /// Move-only RAII for one server-wide slot. Mirrors QuotaSlot's contract so
    /// every DownloadUpdate exit path releases exactly once.
    class Slot {
      public:
        Slot() = default;
        explicit Slot(std::atomic<int>* c) : counter_(c) {}
        Slot(Slot&& o) noexcept : counter_(o.counter_) { o.counter_ = nullptr; }
        Slot& operator=(Slot&& o) noexcept {
            if (this != &o) {
                reset();
                counter_ = o.counter_;
                o.counter_ = nullptr;
            }
            return *this;
        }
        Slot(const Slot&) = delete;
        Slot& operator=(const Slot&) = delete;
        ~Slot() noexcept { reset(); }
        void reset() noexcept {
            if (counter_) {
                counter_->fetch_sub(1, std::memory_order_acq_rel);
                counter_ = nullptr;
            }
        }
        [[nodiscard]] bool held() const noexcept { return counter_ != nullptr; }

      private:
        std::atomic<int>* counter_{nullptr};
    };

    /// The ceiling THIS caller may occupy.
    ///
    /// Two ceilings, not one. An IP-keyed caller — which is what an
    /// unauthenticated peer is on a deployment where the identity gate is inert
    /// — may occupy only the unreserved share, so commanding more addresses buys
    /// it no more of the ceiling. A certificate-keyed peer may use the whole cap.
    ///
    /// The protection is proportional, not absolute, and the floor below is where
    /// it runs out: at `max_concurrent_total = 1` there is one slot and the floor
    /// gives it to whoever asks first, IP-keyed or not. A deployment that needs
    /// the reserve to mean anything needs a ceiling with room to divide.
    ///
    /// FLOORED AT ONE, for the reserve arithmetic ONLY. Integer division makes
    /// the unreserved share round to zero for a small cap — at
    /// `max_concurrent_total=1` a 50% reserve would leave IP-keyed peers no
    /// capacity at all, and where the identity gate is inert EVERY peer is
    /// IP-keyed, so that is a total OTA outage produced by a reserve meant to
    /// protect availability. An operator who configured no capacity at all still
    /// gets none: the floor exists so rounding cannot turn configured capacity
    /// into zero for the majority case, not to manufacture capacity nobody asked
    /// for.
    [[nodiscard]] static constexpr int effective_cap(int max_total, int cert_reserve_pct,
                                                     bool cert_keyed) noexcept {
        if (cert_keyed)
            return max_total;
        if (max_total <= 0)
            return 0;
        // Widened before multiplying. `max_total` is only `CLI::PositiveNumber`-
        // checked, so anything above ~21.4 million overflows the multiply in `int`
        // — undefined behaviour, which the UBSan nightly leg traps, and which lands
        // on a NEGATIVE product in practice. That product then floors to 1, handing
        // an IP-keyed caller an effective ceiling of one: the operator asked for
        // more capacity and silently received almost none.
        const auto unreserved = static_cast<std::int64_t>(max_total) *
                                std::clamp(100 - cert_reserve_pct, 0, 100) / 100;
        return static_cast<int>(std::max<std::int64_t>(1, unreserved));
    }

    struct Decision {
        bool admitted{false};
        int observed_in_flight{0}; ///< the count BEFORE this call, for the log line
        int effective_cap{0};
        Slot slot; ///< held iff `admitted`
    };

    /// Take a slot, or refuse. Increment-then-check (rather than check-then-
    /// increment) so two callers racing at the ceiling cannot both observe room.
    [[nodiscard]] Decision try_acquire(int max_total, int cert_reserve_pct, bool cert_keyed) {
        const int cap = effective_cap(max_total, cert_reserve_pct, cert_keyed);
        const int prev = in_flight_.fetch_add(1, std::memory_order_acq_rel);
        if (prev >= cap) {
            in_flight_.fetch_sub(1, std::memory_order_acq_rel);
            return Decision{false, prev, cap, Slot{}};
        }
        return Decision{true, prev, cap, Slot{&in_flight_}};
    }

    [[nodiscard]] int in_flight() const noexcept {
        return in_flight_.load(std::memory_order_acquire);
    }

  private:
    /// Atomic rather than mutex-guarded: a single counter on the admission path,
    /// which must not add contention to the per-peer quota's own lock.
    std::atomic<int> in_flight_{0};
};

} // namespace yuzu::server::detail
