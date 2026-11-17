/**
 * file_search_governor.hpp -- the slice governor of the on-demand file search: a duty-cycle
 * pacer with an injected clock and sleep, plus the pure stall/restart bookkeeping. STL only; no
 * real clock, sleep, thread, lock or I/O lives here.
 *
 * pace() is called before each directory listing and from the visit callback before each entry.
 * It reads the clock once and returns at once unless a whole work_quantum of work has passed, so
 * a per-entry call is cheap and a 50,000-entry flat listing is paced like any other work.
 *
 * GovernorState is plain data on purpose: nothing here stores it; a caller that needs it across
 * slices persists it behind a write-ahead marker.
 */
#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
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
};

[[nodiscard]] inline bool valid(const GovernorLimits& l) noexcept {
    return l.slice.count() > 0 && l.work_quantum.count() > 0 && l.duty_percent >= 1 &&
           l.duty_percent <= 100;
}

struct GovernorEnv {
    std::function<Clock::time_point()> now;
    std::function<void(std::chrono::milliseconds)> sleep;
};

class SliceGovernor {
public:
    SliceGovernor(const GovernorLimits& limits, GovernorEnv env)
        : limits_(limits), env_(std::move(env)), last_resume_(env_.now()),
          deadline_(last_resume_ + limits.slice) {}

    [[nodiscard]] Clock::time_point deadline() const noexcept { return deadline_; }

    void pace() {
        const auto t = env_.now();
        const auto work = std::chrono::duration_cast<std::chrono::milliseconds>(t - last_resume_);
        if (work < limits_.work_quantum)
            return;
        if (limits_.duty_percent >= 100 || t >= deadline_) {
            last_resume_ = t;
            return;
        }
        // valid() refuses a zero duty and the caller gates on it; one that still arrives is paced as
        // 1 %, the gentlest setting, never divided by.
        auto nap = work * (100 - limits_.duty_percent) / std::max(limits_.duty_percent, 1u);
        // Never sleep to or past the deadline: leave at least 1 ms of slice.
        const auto room = std::chrono::duration_cast<std::chrono::milliseconds>(deadline_ - t) -
                          std::chrono::milliseconds{1};
        if (nap > room)
            nap = room;
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
};

enum class Health { ok, stalled, unstable };

struct GovernorState {
    unsigned consecutive_stalls{0};
    unsigned restarts{0};
    Health health{Health::ok};
};

// Pure. A restart legitimately returns an earlier position, so it is never a stall and takes
// precedence over `advanced`. Any non-ok health is sticky.
[[nodiscard]] inline GovernorState record_slice(GovernorState s, const GovernorLimits& l,
                                                bool advanced, bool restarted) noexcept {
    if (restarted) {
        ++s.restarts;
        if (s.restarts >= l.max_restarts && s.health == Health::ok)
            s.health = Health::unstable;
    } else if (advanced) {
        s.consecutive_stalls = 0;
    } else {
        ++s.consecutive_stalls;
        if (s.consecutive_stalls >= l.max_stalls && s.health == Health::ok)
            s.health = Health::stalled;
    }
    return s;
}

} // namespace yuzu::shared::file_search
