#pragma once

/// @file kek_rotate_control.hpp
/// #2530 (T3a) — pure decision helpers for the KEK rotate control flow.
///
/// Pulled out of the `kek_ops.rotate` seam closure in server.cpp so the
/// load-bearing ORDERING (contract B3) and the half-commit-wins classification
/// (contract B4) can be exercised by a fast, Postgres-free Catch2 test instead
/// of only through a live rotate against a real database. server.cpp is the
/// only production includer; every DB read (`SecretCodec::rotate_clock`,
/// `live_kek_version_count`) still happens there — this header only decides
/// what a given set of already-read values MEANS.
///
/// Do not add a Postgres/codec dependency here — that would defeat the point.

#include "kek_routes.hpp"
#include "pg/secret_codec.hpp"

#include <chrono>
#include <cstdint>
#include <limits>
#include <string_view>

namespace yuzu::server::detail {

/// #2530 B5 — the shipped default for `--kek-max-live-versions`
/// (server.hpp's `Config::kek_max_live_versions` and main.cpp's
/// `->default_val(...)` both independently carry this same number, matching
/// the rest of this codebase's flag/Config-default convention). This
/// constant is the single source of truth for the ONE thing that must never
/// drift between two DIFFERENT call sites: main.cpp's boot-time
/// spdlog::warn and server.cpp's `server.kek_ceiling_raised` audit event
/// must agree on exactly what counts as "above default" (see
/// `kek_ceiling_is_risk_acceptance` below) — a mismatch there would let one
/// fire without the other.
constexpr int kKekMaxLiveVersionsDefault = 32;

/// True iff `configured` is a deliberate, above-default risk acceptance
/// (#2530 B5). Raising `--kek-max-live-versions` above the default is the
/// supported escape hatch that keeps rotation usable once an install hits
/// the ceiling (there is no retire route, #2525) — crossing this threshold
/// must be loud: a boot-time spdlog::warn (main.cpp) AND a
/// `server.kek_ceiling_raised` audit event (server.cpp, once audit_store_
/// exists), both gated on this same predicate.
[[nodiscard]] constexpr bool kek_ceiling_is_risk_acceptance(int configured) {
    return configured > kKekMaxLiveVersionsDefault;
}

/// #2530 B3 steps 1-3, in the exact contract order. Given the two durable
/// reads (`rotate_clock()`, `live_kek_version_count()`) and the two
/// operator-configured limits, decides whether a rotate may proceed.
///
/// `failure == KekOpResult::Failure::None` means "every precondition passed —
/// proceed to step 5 (mint)". (A former step 4, stamping a process-local
/// cooldown, was removed — #2530 G7-S9 — once it was superseded by the
/// durable checks this function performs; see the removal comment at the
/// `kek_ops.rotate` seam in server.cpp.) Any other value means STOP; the
/// caller must return immediately without calling `rotate_kek()`.
///
/// Order is load-bearing (contract B3): clock anomaly is checked BEFORE the
/// durable cooldown, which is checked BEFORE the version ceiling. A future
/// edit must not reorder these three `if`s — a clock anomaly must never be
/// reported as an ordinary Cooldown (the timestamp a Cooldown's
/// `retry_after_ms` would be computed from is the very thing just proven
/// untrustworthy), and the ceiling must never be evaluated (let alone trip)
/// while the clock or cooldown checks would have stopped first.
struct RotatePreconditionOutcome {
    KekOpResult::Failure failure{KekOpResult::Failure::None};
    /// Only meaningful when `failure == Cooldown`. Honest milliseconds
    /// remaining on `--kek-min-rotate-interval`, derived from the SAME
    /// database-server timestamp `rotate_clock()` read (never the app-host
    /// clock) — this is what makes the retry hint truthful (contract D).
    std::uint32_t cooldown_retry_after_ms{0};
    /// #2530 G7-B6: only meaningful when `failure == ClockAnomaly`. The
    /// magnitude, in seconds, of how far into the future the newest
    /// `kek_meta` row is dated (`RotateClock::future_skew_secs`) — carried
    /// through so the seam can report it in the 503 body and log line rather
    /// than only in an internal boolean.
    std::uint64_t clock_skew_secs{0};
};

[[nodiscard]] inline RotatePreconditionOutcome evaluate_rotate_preconditions(
    const pg::SecretCodec::RotateClock& clock, std::chrono::seconds min_rotate_interval,
    std::size_t live_version_count, std::uint32_t max_live_versions) {
    // Step 1.
    if (clock.clock_anomaly)
        return {KekOpResult::Failure::ClockAnomaly, 0, clock.future_skew_secs};
    // Step 2. `any_rows == false` means no kek_meta row exists yet (first
    // boot) — nothing to be cooling down from.
    if (clock.any_rows && clock.since_newest < min_rotate_interval) {
        const auto remaining = min_rotate_interval - clock.since_newest;
        const std::int64_t remaining_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(remaining).count();
        // Saturate rather than truncate (post-review fix): the field is a
        // `std::uint32_t`, and `--kek-min-rotate-interval` was originally
        // bounded only by CLI::PositiveNumber at the flag (no upper bound
        // before this fix — main.cpp now caps it at 365d as a sanity
        // ceiling, NOT operator guidance to size this runaway guard to a
        // rotation cadence; see that flag's help text). A configured
        // interval past ~49.7 days (2^32 ms) produces a `remaining_ms` that
        // OVERFLOWS a uint32 and wraps to a near-ZERO hint, which is the
        // exact honesty violation this field exists to prevent (contract D:
        // Cooldown is the ONE failure where a retry hint is truthful,
        // precisely because waiting resolves it — a wrapped hint invites a
        // retry storm instead).
        // Saturating at UINT32_MAX is the safe failure direction: an
        // over-long hint just makes the caller wait longer than strictly
        // necessary (safe), where a wrapped short hint actively invites
        // hammering the endpoint. main.cpp additionally bounds the flag
        // itself so this clamp is defence-in-depth, not the only guard.
        const std::uint32_t retry_after_ms =
            (remaining_ms > static_cast<std::int64_t>(std::numeric_limits<std::uint32_t>::max()))
                ? std::numeric_limits<std::uint32_t>::max()
                : static_cast<std::uint32_t>(remaining_ms);
        return {KekOpResult::Failure::Cooldown, retry_after_ms};
    }
    // Step 3.
    if (live_version_count >= max_live_versions)
        return {KekOpResult::Failure::VersionCeiling, 0};
    return {}; // every precondition passed
}

/// #2530 B4 — classify a `rotate_kek()` mint failure. `version_advanced` is
/// `active_kek_version()` observed strictly higher AFTER the call than
/// BEFORE it (the existing #2395 before/after comparison, server.cpp
/// ~L12662, which stays authoritative and MUST be evaluated first).
///
/// Half-commit classification WINS over everything else, including a
/// `query_canceled` kind on the underlying error: `rotate_kek()`'s only
/// failure path after the mint commits is an internal `rewrap_all()` error,
/// and whatever kind THAT carries, the operator must still be told to call
/// `/rewrap`, never to retry `/rotate` — retrying `/rotate` on a
/// half-committed rotation mints a spurious, unretirable (#2525) extra
/// version every single time. Only refine to `QueryCanceled` when the
/// version did NOT advance, i.e. the cancellation happened strictly before
/// any commit — a clean, safe-to-retry-`/rotate` failure.
[[nodiscard]] inline KekOpResult::Failure
classify_rotate_mint_failure(bool version_advanced, pg::SecretCodec::LifecycleError::Kind kind) {
    if (version_advanced)
        return KekOpResult::Failure::HalfCommitted;
    return (kind == pg::SecretCodec::LifecycleError::Kind::query_canceled)
               ? KekOpResult::Failure::QueryCanceled
               : KekOpResult::Failure::Internal;
}

/// #2530 B7 — the fixed Prometheus outcome vocabulary for
/// `yuzu_server_kek_operations_total{op,outcome}`. Mirrors `failure_tag` in
/// kek_routes.cpp (same switch shape, same nine tokens) minus the
/// `"failure="` prefix that string carries for the audit `detail` column —
/// this one is a bare Prometheus label value. `None` is the one case
/// `failure_tag` never sees (routes only call it on a non-None failure);
/// here it is the success path, so it gets its own label instead of falling
/// through to "internal".
[[nodiscard]] inline std::string_view kek_op_outcome_label(KekOpResult::Failure f) {
    switch (f) {
    case KekOpResult::Failure::None:
        return "success";
    case KekOpResult::Failure::Unavailable:
        return "unavailable";
    case KekOpResult::Failure::Conflict:
        return "conflict";
    case KekOpResult::Failure::Cooldown:
        return "cooldown";
    case KekOpResult::Failure::VersionCeiling:
        return "ceiling";
    case KekOpResult::Failure::QueryCanceled:
        return "query_canceled";
    case KekOpResult::Failure::ClockAnomaly:
        return "clock_anomaly";
    case KekOpResult::Failure::HalfCommitted:
        return "half_committed";
    case KekOpResult::Failure::Internal:
        return "internal";
    }
    return "internal";
}

} // namespace yuzu::server::detail
