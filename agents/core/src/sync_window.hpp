#pragma once

/// @file sync_window.hpp
/// Pure placement core for a sync source's maintenance window (ADR-0016 update):
/// "fire at a stable per-agent moment inside [start, end) local time". The wall
/// clock is injected as a LocalClock so the DST edge cases unit-test on a fake
/// transition table; only system_local_clock() touches the C library.

#include <cstdint>
#include <ctime>
#include <functional>

namespace yuzu::agent {

/// A same-day window in minutes after local midnight; start_min < end_min.
struct SyncWindow {
    int start_min{0};
    int end_min{0};
};

/// Injected local-time conversions over the C library's broken-down time (`std::tm`).
/// from_local MUST normalise out-of-range fields (tm_mday = 32 is the first of the next
/// month, as mktime does), decide DST itself (the argument's tm_isdst belongs to the
/// instant to_local was given, not to the requested time) and resolve a non-existent
/// local time (a spring-forward gap) forward.
struct LocalClock {
    std::function<std::tm(std::int64_t)> to_local;
    std::function<std::int64_t(const std::tm&)> from_local;
};

/// The machine's local zone through the C library; DST is the library's.
inline LocalClock system_local_clock() {
    LocalClock c;
    c.to_local = [](std::int64_t t) {
        const std::time_t tt = static_cast<std::time_t>(t);
        std::tm tmv{};
        // The conversion's return value is deliberately unchecked: on failure tmv stays
        // zeroed (year 1900), so mktime yields a pre-epoch value or -1 (libc-dependent),
        // both candidates fail `cand <= now`, and next_window_fire returns its now + 24 h
        // fallback.
#ifdef _WIN32
        (void)localtime_s(&tmv, &tt);
#else
        (void)localtime_r(&tt, &tmv);
#endif
        return tmv;
    };
    c.from_local = [](const std::tm& l) {
        std::tm tmv = l; // mktime normalises in place
        tmv.tm_isdst = -1; // let the library decide
        return static_cast<std::int64_t>(std::mktime(&tmv));
    };
    return c;
}

/// Next epoch second strictly after `now` at which an agent with `phase_hash`
/// fires: its stable offset inside the window (second resolution) on today's local
/// date, or on tomorrow's once today's has passed. If the library cannot convert
/// the local time, falls back to now + 24 h rather than to a past instant.
inline std::int64_t next_window_fire(std::int64_t now, SyncWindow w, std::uint64_t phase_hash,
                                     const LocalClock& clock) {
    constexpr std::int64_t kDay = 24 * 60 * 60;
    const std::int64_t span = static_cast<std::int64_t>(w.end_min - w.start_min) * 60;
    if (span <= 0)
        return now + kDay;
    const std::int64_t off = static_cast<std::int64_t>(w.start_min) * 60 +
                             static_cast<std::int64_t>(phase_hash % static_cast<std::uint64_t>(span));
    std::tm l = clock.to_local(now);
    l.tm_hour = static_cast<int>(off / 3600);
    l.tm_min = static_cast<int>(off % 3600 / 60);
    l.tm_sec = static_cast<int>(off % 60);
    std::int64_t cand = clock.from_local(l);
    if (cand <= now) {
        ++l.tm_mday;
        cand = clock.from_local(l);
    }
    return cand > now ? cand : now + kDay;
}

} // namespace yuzu::agent
