/**
 * file_search_governor.hpp -- the slice governor of the on-demand file search: a duty-cycle pacer with
 * an adaptive listing back-off, an injected clock and sleep, plus the pure stall/restart bookkeeping.
 * STL only; no real clock, sleep, thread, lock or I/O lives here.
 *
 * pace() is called before each directory listing and from the visit callback before each entry.
 * It reads the clock once and returns at once unless a whole work_quantum of work has passed, so
 * a per-entry call is cheap and a 50,000-entry flat listing is paced like any other work.
 *
 * What is measured: the driver times each directory listing with the same injected clock and hands
 * the span to note_listing(). Nothing else is measured, and nothing is read from the clock there.
 * The rule: a listing is slow when it takes at least slow_list_hard, or when it takes at least
 * slow_list_floor and at least slow_list_ratio times the fastest of this slice's last kLatencyRing
 * listings (the baseline adapts: a slow listing is stored too, so an evenly slow disk stops counting
 * once the ring holds only its listings). A slow listing starts or doubles a back-off, capped at
 * max_backoff_pause; a listing that is not slow halves the back-off, and a back-off below one
 * work_quantum is dropped.
 * pace() adds the back-off to the duty nap, never more than half of the slice's remaining room, so
 * the back-off alone cannot sleep a slice to its deadline, and the total never reaches it. With no
 * back-off pace() is the plain duty cycle, call for call. The back-off only lengthens a nap: it can
 * slow a search down, never speed it up.
 *
 * What "healthy" means here: a disk on which no listing is slow by the rule above, and nothing more.
 * The span is the whole listing, not divided by its entry count, and the baseline includes listings
 * served from cache, so a very large directory, or a cold listing after cached ones, can read as slow
 * on a disk that is not saturated. The cost is bounded: one work_quantum added to a nap after an
 * isolated slow listing, dropped by the next listing that is not slow (one quantum halves to less
 * than a quantum); a run of slow listings doubles it up to max_backoff_pause. On seek-bound media
 * with a cold cache that could hold a search well under half duty. Reasoned, not measured.
 *
 * State is per slice: a slice builds a new governor, so the ring and the back-off start empty each
 * time and nothing is carried in a cursor. Nothing is reported: no row, tag or log field carries it.
 *
 * GovernorState is plain data on purpose: nothing here stores it. The restart count needs no
 * store: record_slice takes it from the cursor (Cursor::generation), so a replayed slice counts
 * once and a caller whose only memory is the cursor still reaches `unstable`. The stall count is
 * the consecutive attempts on ONE cursor (a stall issues no cursor, so no cursor field carries
 * it): the retrying caller keeps consecutive_stalls in memory between attempts, nothing is
 * persisted, and a restart starts it again; one that keeps nothing must not retry. A slice that
 * returned no result (it threw, timed out or was refused a worker) is a stall too:
 * record_failed_slice.
 */
#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <utility>

namespace yuzu::shared::file_search {

using Clock = std::chrono::steady_clock;

struct GovernorLimits {
    std::chrono::milliseconds slice{10'000};
    std::size_t max_entries{400'000};
    std::size_t max_rows{1'000};
    unsigned duty_percent{50};
    std::chrono::milliseconds work_quantum{50};
    unsigned max_stalls{3};
    unsigned max_restarts{3};
    // The listing back-off: see the banner for the rule. These defaults are reasoned, not measured on
    // a saturated disk.
    std::chrono::milliseconds slow_list_floor{20};
    unsigned slow_list_ratio{4};
    std::chrono::milliseconds slow_list_hard{250};
    std::chrono::milliseconds max_backoff_pause{1'000};
};

// The longest slice valid() accepts (one hour). The governor clamps any slice to [0, kMaxSlice], so
// its deadline sum cannot overflow unless the injected clock reads within an hour of its maximum.
inline constexpr std::chrono::milliseconds kMaxSlice{3'600'000};

// The listing latencies a governor remembers for its baseline.
inline constexpr std::size_t kLatencyRing = 8;

// A zero max_stalls or max_restarts is refused, not read as 1: record_slice would otherwise turn the
// very first slice into a stall or a restart verdict. The back-off fields are refused when they could
// never act (a hard bound past the slice, a cap below one quantum) or could overflow a compare.
[[nodiscard]] inline bool valid(const GovernorLimits& l) noexcept {
    return l.slice.count() > 0 && l.slice <= kMaxSlice && l.work_quantum.count() > 0 &&
           l.work_quantum <= l.slice && l.duty_percent >= 1 && l.duty_percent <= 100 &&
           l.max_stalls >= 1 && l.max_restarts >= 1 && l.slow_list_floor.count() > 0 &&
           l.slow_list_hard >= l.slow_list_floor && l.slow_list_hard <= l.slice &&
           l.slow_list_ratio >= 2 && l.slow_list_ratio <= 64 &&
           l.max_backoff_pause >= l.work_quantum && l.max_backoff_pause <= l.slice;
}

struct GovernorEnv {
    std::function<Clock::time_point()> now;
    std::function<void(std::chrono::milliseconds)> sleep;
};

class SliceGovernor {
public:
    SliceGovernor(const GovernorLimits& limits, GovernorEnv env)
        : limits_(limits), env_(std::move(env)), last_resume_(env_.now()),
          deadline_(last_resume_ +
                    std::clamp(limits.slice, std::chrono::milliseconds{0}, kMaxSlice)) {}

    [[nodiscard]] Clock::time_point deadline() const noexcept { return deadline_; }

    /// Records how long one directory listing took, from the caller's own clock reads. Pure state
    /// arithmetic: no allocation, no clock read, never throws. Any span is accepted: it is clamped to
    /// [0, kMaxSlice] first, so a clock that stepped back or an absurd span cannot overflow a compare.
    void note_listing(Clock::duration took) noexcept {
        using std::chrono::microseconds;
        using std::chrono::milliseconds;
        // Every limit is read through this clamp: an unvalidated one can neither overflow nor go negative.
        const auto bounded = [](milliseconds m) { return std::clamp(m, milliseconds{0}, kMaxSlice); };
        const auto span = std::clamp(took, Clock::duration::zero(),
                                     std::chrono::duration_cast<Clock::duration>(kMaxSlice));
        const std::int64_t us = std::chrono::duration_cast<microseconds>(span).count();

        bool slow = us >= microseconds{bounded(limits_.slow_list_hard)}.count();
        if (!slow && count_ > 0 && us >= microseconds{bounded(limits_.slow_list_floor)}.count()) {
            std::int64_t fastest = ring_[0];
            for (std::size_t i = 1; i < count_; ++i)
                fastest = (std::min)(fastest, ring_[i]);
            slow = us >= fastest * static_cast<std::int64_t>((std::min)(limits_.slow_list_ratio, 64u));
        }
        ring_[next_] = us; // judged first, then stored: the baseline adapts, slow ones included
        next_ = (next_ + 1) % kLatencyRing;
        count_ = (std::min)(count_ + 1, kLatencyRing);

        const milliseconds cap = bounded(limits_.max_backoff_pause);
        if (slow) {
            backoff_ = backoff_.count() == 0 ? (std::min)((std::max)(limits_.work_quantum, milliseconds{1}), cap)
                                             : (backoff_ > cap / 2 ? cap : backoff_ * 2);
        } else {
            backoff_ /= 2;
            if (backoff_ < limits_.work_quantum)
                backoff_ = milliseconds{0};
        }
    }

    void pace() {
        const auto t = env_.now();
        const auto work = std::chrono::duration_cast<std::chrono::milliseconds>(t - last_resume_);
        if (work < limits_.work_quantum)
            return;
        if (t >= deadline_) {
            last_resume_ = t;
            return;
        }
        // The duty nap: none at 100 %. valid() refuses a zero duty and the caller gates on it; one
        // that still arrives is paced as 1 %, the gentlest setting, never divided by.
        std::chrono::milliseconds nap{0};
        if (limits_.duty_percent < 100)
            nap = work * (100 - limits_.duty_percent) / (std::max)(limits_.duty_percent, 1u);
        // Never sleep to or past the deadline: leave at least 1 ms of slice.
        const auto room = std::chrono::duration_cast<std::chrono::milliseconds>(deadline_ - t) -
                          std::chrono::milliseconds{1};
        if (nap > room)
            nap = room;
        else if (room > nap && backoff_.count() > 0) // never more than half of what is left
            nap += (std::min)(backoff_, (room - nap) / 2);
        if (nap.count() > 0) {
            env_.sleep(nap);
            last_resume_ = env_.now();
        } else {
            last_resume_ = t;
        }
    }

private:
    GovernorLimits limits_;
    GovernorEnv env_;
    Clock::time_point last_resume_;
    Clock::time_point deadline_;
    std::array<std::int64_t, kLatencyRing> ring_{}; // listing latencies in microseconds, oldest overwritten
    std::size_t next_{0};
    std::size_t count_{0};
    std::chrono::milliseconds backoff_{0}; // 0 when healthy
};

enum class Health { ok, stalled, unstable };

struct GovernorState {
    unsigned consecutive_stalls{0};
    std::uint64_t restarts{0}; // the cursor's count after the last slice: derived, not accumulated
    Health health{Health::ok};
};

// Pure. A restart legitimately returns an earlier position, so it is never a stall and takes
// precedence over `advanced`. Any non-ok health is sticky.
// `generation` is the Cursor::generation the slice resumed from; a zero max_restarts acts as 1.
[[nodiscard]] inline GovernorState record_slice(GovernorState s, const GovernorLimits& l,
                                                bool advanced, bool restarted,
                                                std::uint32_t generation) noexcept {
    s.restarts = std::uint64_t{generation} + (restarted ? 1u : 0u);
    if (s.restarts >= (std::max)(l.max_restarts, 1u) && s.health == Health::ok)
        s.health = Health::unstable;
    if (!restarted) { // a restart is never a stall: the stall count stands
        if (advanced)
            s.consecutive_stalls = 0;
        else if (++s.consecutive_stalls >= l.max_stalls && s.health == Health::ok)
            s.health = Health::stalled;
    }
    return s;
}

/// The failure input: a slice that returned no result is a non-advancing attempt on its cursor.
[[nodiscard]] inline GovernorState record_failed_slice(GovernorState s, const GovernorLimits& l,
                                                       std::uint32_t generation) noexcept {
    return record_slice(s, l, false, false, generation);
}

} // namespace yuzu::shared::file_search
