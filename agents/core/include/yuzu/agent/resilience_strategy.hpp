#pragma once

/**
 * resilience_strategy.hpp — per-rule enforcement retry policy for Guardian guards
 * (design docs/yuzu-guardian-design-v1.1.md §8.5).
 *
 * Pure, platform-independent decision logic with an INJECTED clock, so the three
 * modes are unit-testable deterministically on any OS without sleeps. A guard
 * consults decide() before each enforce remediation (a value write OR a key
 * recreate). The strategy gates ONLY the remediation — detection and event
 * emission always happen regardless of what decide() returns, so a backed-off or
 * given-up guard still reports drift.
 *
 *   Persist  — remediate immediately on every drift; sub-ms; never give up (default).
 *   Backoff  — exponential delay between re-enforcements (initial × 2ⁿ, capped);
 *              never gives up. Trades latency for calm against a noisy adversary.
 *   Bounded  — give up after N consecutive re-fix cycles in one fight; a quiet
 *              window resets the counter; on give-up stop fixing (keep detecting)
 *              and stay given-up until an admin re-pushes — unless `resume_after`
 *              schedules an automatic retry.
 *
 * Modes apply in ENFORCE mode only; an audit guard never calls decide().
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::agent {

enum class ResilienceMode { Persist, Backoff, Bounded };

/// Parse "persist" | "backoff" | "bounded" (case-insensitive). Unknown/empty →
/// Persist (the safe default — immediate enforcement, never give up).
YUZU_EXPORT ResilienceMode parse_resilience_mode(std::string_view s);

struct ResilienceConfig {
    ResilienceMode mode{ResilienceMode::Persist};
    /// Bounded: give up after this many consecutive re-fix cycles in one fight.
    std::uint32_t max_attempts{5};
    /// Sustained no-drift gap that resets the Bounded counter / Backoff exponent.
    /// Reactive — evaluated at the next drift, never as a scheduled wake. Does NOT
    /// un-give-up a Bounded guard (that needs `resume_after` or a re-push).
    std::uint64_t quiet_reset_ms{60000};
    /// Bounded: after giving up, auto-resume remediation this long later.
    /// 0 = stay given-up until an admin re-pushes (no auto-resume).
    std::uint64_t resume_after_ms{0};
    /// Backoff: delay between re-enforcements; initial, doubled each remediation up
    /// to max.
    std::uint64_t backoff_initial_ms{1000};
    std::uint64_t backoff_max_ms{60000};
};

/// Canonical param keys for the resilience policy in a rule's `remediation.params`
/// (design §8.5). THIS is the single source of truth: the agent parses these, and the
/// C3b server JSON-schema + C3c dashboard form MUST emit exactly these keys (and the
/// seconds-suffixed ones in seconds). Keep all three in lockstep with this list.
namespace resilience_keys {
inline constexpr std::string_view kMode = "mode";                       // persist|backoff|bounded
inline constexpr std::string_view kMaxAttempts = "max_attempts";        // Bounded cycle cap
inline constexpr std::string_view kQuietResetS = "quiet_reset_s";       // seconds
inline constexpr std::string_view kResumeAfterS = "resume_after_s";     // seconds (0 = none)
inline constexpr std::string_view kBackoffInitialMs = "backoff_initial_ms";
inline constexpr std::string_view kBackoffMaxMs = "backoff_max_ms";
inline constexpr std::string_view kEventDebounceMs = "event_debounce_ms";
} // namespace resilience_keys

/// The implicit legacy event-debounce default every non-spark call site relies on
/// (#3531: single-sourced so a future change here can't silently leave a stale copy
/// behind — guardian_spark_bridge.hpp's own fallback for an unhandled SparkType
/// reuses this constant rather than repeating the literal).
inline constexpr std::uint64_t kGuardianLegacyDebounceMs = 1000;

/// Build a ResilienceConfig from a param lookup (`get(key)` returns the value or ""
/// when absent) and write the event-debounce window (ms) to `event_debounce_ms_out`.
/// Proto-free by design — the agent passes a lookup over the proto map; tests pass a
/// lookup over a plain map — so the key names + unit conversions + defaults are
/// deterministically unit-testable. Unknown/garbage values fall back to the default.
///
/// `default_event_debounce_ms` (#3388): every LEGACY call site relies on the
/// kGuardianLegacyDebounceMs implicit default, which suits legacy's notification-
/// driven model (no scheduled re-evaluation) - leave it unset there. Spark's
/// convergence scheduler re-evaluates every armed rule on a fixed per-type cadence,
/// so that default expires before every sweep and a persistently-drifted rule
/// re-emits on every one; the spark call site passes its own lane-aware default
/// instead (`guardian_spark_bridge.hpp`).
YUZU_EXPORT ResilienceConfig
parse_resilience_params(const std::function<std::string(std::string_view)>& get,
                        std::uint64_t& event_debounce_ms_out,
                        std::uint64_t default_event_debounce_ms = kGuardianLegacyDebounceMs);

/// Outcome of decide(). The guard ALWAYS detects + emits; this only governs the
/// remediation write/create and when the watch should wake itself next.
struct ResilienceDecision {
    bool remediate{true};                       ///< perform the write/create now?
    std::optional<std::uint64_t> next_wake_ms;  ///< schedule a self-wake (backoff retry / resume cooldown); nullopt = block on OS events only (quiescent)
    bool gave_up{false};                        ///< Bounded: currently in the given-up state (event marker)
};

/// Single-threaded: a guard owns one strategy and only its watch thread calls
/// decide(). No internal synchronisation.
class YUZU_EXPORT ResilienceStrategy {
public:
    explicit ResilienceStrategy(ResilienceConfig cfg) : cfg_(cfg) {}

    /// Called on each DETECTED drift, in enforce mode only. `now_ms` is a monotonic
    /// millisecond timestamp injected by the caller (deterministic in tests).
    ResilienceDecision decide(std::uint64_t now_ms);

    ResilienceMode mode() const { return cfg_.mode; }

private:
    ResilienceConfig cfg_;

    bool have_last_drift_{false};
    std::uint64_t last_drift_ms_{0};

    // Bounded state
    std::uint32_t cycles_{0};
    bool given_up_{false};
    std::uint64_t given_up_at_ms_{0};

    // Backoff state
    bool have_last_remediation_{false};
    std::uint64_t last_remediation_ms_{0};
    std::uint64_t backoff_cur_ms_{0}; // current inter-remediation window (0 = none yet)
};

} // namespace yuzu::agent
