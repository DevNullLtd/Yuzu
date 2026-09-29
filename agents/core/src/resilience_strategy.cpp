/**
 * resilience_strategy.cpp — see resilience_strategy.hpp.
 *
 * Pure decision logic; no OS calls, no clock of its own (the caller injects now_ms).
 */

#include <yuzu/agent/resilience_strategy.hpp>

#include <algorithm> // std::min
#include <cctype>    // std::tolower
#include <charconv>  // std::from_chars
#include <limits>    // std::numeric_limits
#include <string>

namespace yuzu::agent {
namespace {
std::uint64_t to_u64(const std::string& v, std::uint64_t dflt) {
    if (v.empty()) return dflt;
    std::uint64_t out = dflt;
    auto [p, ec] = std::from_chars(v.data(), v.data() + v.size(), out);
    // Whole-string match only — "123abc" / "1.5" / "12 " are garbage → default,
    // not a silent 123/1/12. The server validates numeric params the same way, so
    // the two boundaries agree on what a number is (M1).
    return (ec == std::errc{} && p == v.data() + v.size()) ? out : dflt;
}

// Authored-seconds → milliseconds, saturating instead of wrapping u64 when the
// seconds value is absurd. The server already range-checks seconds, but the agent
// must never let `* 1000` wrap into a tiny window (defence-in-depth; MEDIUM).
std::uint64_t seconds_to_ms(std::uint64_t secs) {
    constexpr std::uint64_t kMax = std::numeric_limits<std::uint64_t>::max() / 1000;
    return secs > kMax ? std::numeric_limits<std::uint64_t>::max() : secs * 1000;
}
} // namespace

ResilienceConfig parse_resilience_params(const std::function<std::string(std::string_view)>& get,
                                         std::uint64_t& event_debounce_ms_out,
                                         std::uint64_t default_event_debounce_ms) {
    using namespace resilience_keys;
    ResilienceConfig c;
    c.mode = parse_resilience_mode(get(kMode));
    c.max_attempts = static_cast<std::uint32_t>(to_u64(get(kMaxAttempts), 5));
    c.quiet_reset_ms = seconds_to_ms(to_u64(get(kQuietResetS), 60));  // authored in seconds
    c.resume_after_ms = seconds_to_ms(to_u64(get(kResumeAfterS), 0)); // authored in seconds
    c.backoff_initial_ms = to_u64(get(kBackoffInitialMs), 1000);
    c.backoff_max_ms = to_u64(get(kBackoffMaxMs), 60000);
    event_debounce_ms_out = to_u64(get(kEventDebounceMs), default_event_debounce_ms);
    return c;
}

ResilienceMode parse_resilience_mode(std::string_view s) {
    std::string l;
    l.reserve(s.size());
    for (char c : s)
        l.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    if (l == "backoff") return ResilienceMode::Backoff;
    if (l == "bounded") return ResilienceMode::Bounded;
    return ResilienceMode::Persist; // default + unknown
}

ResilienceDecision ResilienceStrategy::decide(std::uint64_t now_ms) {
    // Quiet-reset (reactive): a sustained gap since the last drift means the fight
    // cooled, so reset the Bounded counter / Backoff exponent at THIS drift. It must
    // never un-give-up a Bounded guard — that is gated below on `resume_after`.
    const bool quiet = have_last_drift_ && (now_ms - last_drift_ms_) >= cfg_.quiet_reset_ms;
    have_last_drift_ = true;
    last_drift_ms_ = now_ms;

    switch (cfg_.mode) {
    case ResilienceMode::Persist:
        // Always fix now, no scheduled wake, never give up. This is the sub-ms hot
        // path — keep it a trivial yes (see the Persist regression test).
        return {true, std::nullopt, false};

    case ResilienceMode::Backoff: {
        if (quiet) { // fight cooled — drop back to the initial aggression
            backoff_cur_ms_ = 0;
            have_last_remediation_ = false;
        }
        const std::uint64_t window = backoff_cur_ms_;
        const bool past = !have_last_remediation_ || (now_ms - last_remediation_ms_) >= window;
        if (past) {
            last_remediation_ms_ = now_ms;
            have_last_remediation_ = true;
            // Grow for next time: initial, then double up to the cap. Clamp BEFORE
            // doubling — `backoff_cur_ms_ * 2` evaluated first would wrap u64 for an
            // absurd backoff_max_ms and make std::min pick the tiny wrapped value, a
            // far-shorter-than-intended window. If doubling would exceed the cap, just
            // take the cap (overflow-safe; MEDIUM).
            backoff_cur_ms_ = (backoff_cur_ms_ == 0)        ? cfg_.backoff_initial_ms
                              : (backoff_cur_ms_ > cfg_.backoff_max_ms / 2) ? cfg_.backoff_max_ms
                                                                           : backoff_cur_ms_ * 2;
            return {true, std::nullopt, false};
        }
        // Inside the backoff window: skip the fix (still detect/emit), and wake when
        // the window expires to retry — Backoff never gives up.
        const std::uint64_t remaining = window - (now_ms - last_remediation_ms_);
        return {false, remaining, false};
    }

    case ResilienceMode::Bounded: {
        if (given_up_) {
            if (cfg_.resume_after_ms == 0)
                return {false, std::nullopt, true}; // stay given-up until a re-push
            const std::uint64_t elapsed = now_ms - given_up_at_ms_;
            if (elapsed < cfg_.resume_after_ms)
                return {false, cfg_.resume_after_ms - elapsed, true}; // cooldown; wake to retry
            // Cooldown elapsed → resume a fresh fight.
            given_up_ = false;
            cycles_ = 0;
        }
        if (quiet) cycles_ = 0;
        ++cycles_;
        if (cfg_.max_attempts != 0 && cycles_ > cfg_.max_attempts) {
            given_up_ = true;
            given_up_at_ms_ = now_ms;
            const std::optional<std::uint64_t> wake =
                cfg_.resume_after_ms == 0 ? std::optional<std::uint64_t>{}
                                          : std::optional<std::uint64_t>{cfg_.resume_after_ms};
            return {false, wake, true}; // give up: stop fixing, keep detecting, alert
        }
        return {true, std::nullopt, false}; // within the cap — fix now
    }
    }
    return {true, std::nullopt, false}; // unreachable (all modes return); keeps MSVC quiet
}

} // namespace yuzu::agent
