#pragma once

/// @file pg_reachability_rules.hpp
/// HA WS-8 (ADR-2002 §12): the PURE readiness rule behind `/readyz`'s
/// `pg_reachable` row — "can THIS replica reach the `yuzu` primary right now?".
/// No I/O, no threads: `PgReachabilityProbe` (pg_reachability_probe.hpp) feeds
/// it a `Snapshot`, and it answers with a `Verdict`. Kept apart so every branch
/// is table-testable (`test_pg_reachability_probe.cpp`).
///
/// WHY THIS EXISTS. Every Postgres store's `is_open()` is latched at
/// construction (#3061), and the pool's connect breaker arms only when a NEW
/// connect fails — with idle connections pooled, or with no traffic, it stays
/// closed while Postgres is gone. So before this rule, `/readyz` stayed green
/// through a Postgres outage, which ADR-2002 §12 / ADR-0031 forbid ("an LB must
/// never be routed to a surface that cannot serve").
///
/// THE CONSTANTS ARE NOT FLAGS, deliberately (pre-implementation review, Q5).
/// The load balancer's own `interval` / `healthy_threshold` /
/// `unhealthy_threshold` are the operator's tuning surface; a second set of
/// server-side knobs would stack two hysteresis layers nobody could reason
/// about. Recovery is therefore ONE success (the LB supplies the hysteresis).
///
/// Timing budget (why `kStaleAfter` is 15s): the normal gap between two
/// successes is at most interval + connect deadline + query deadline =
/// 2 + 5 + 2 = 9s, so 15s never reds a healthy replica with a single host. With a
/// multi-host DSN a reconnect walks the hosts as libpq does for the pool's
/// fresh connections, paying the pool's `connect_timeout` per silent host it
/// meets before the one that answers (so a reconnect behind a silent host can
/// run past kStaleAfter and read `stale` — as slow as the pool's own
/// connects); the probe holds its connection in steady state. A FROZEN backend (a `docker pause`d / black-holed primary whose
/// kernel still ACKs, so no socket-level timeout fires) is normally caught
/// before that by the probe's own client-side deadlines — the query times out
/// (2s), the reconnect times out (5s), two failures ⇒ Unreachable, measured
/// ~11s end to end
/// (scripts/ha/ha-readyz-scenarios.sh, scenario A). `kStaleAfter` is the
/// backstop that holds even if a tick wedges outside those deadlines.

#include <chrono>
#include <cstdint>
#include <limits>

namespace yuzu::server::pg_reachability {

/// Pause between the end of one probe and the start of the next.
inline constexpr std::chrono::milliseconds kProbeInterval{2000};
/// Client-side cap on establishing the probe connection to a single host (the
/// `connect_timeout`, when shorter, applies instead), and the whole wait when no
/// `connect_timeout` applies. In a host list each host address instead gets the
/// pool's effective `connect_timeout` (10s by default), timed as libpq's
/// blocking connect times it, so the probe moves on when the pool does.
/// Enforced by the probe's own poll loop — libpq's `connect_timeout` does not
/// apply to `PQconnectStart`/`PQconnectPoll`.
inline constexpr std::chrono::milliseconds kConnectDeadline{5000};
/// Client-side deadline on the probe query round-trip. Server-side
/// `statement_timeout` cannot bind a frozen backend (and would not survive a
/// transaction-mode pooler), so the probe enforces this itself.
inline constexpr std::chrono::milliseconds kQueryDeadline{2000};
/// Consecutive unreachable probes before the replica reports not-ready. Two,
/// so a single blip (a terminated backend, one lost packet) does not evict a
/// healthy replica.
inline constexpr int kFailThreshold = 2;
/// No success for this long ⇒ not ready, whatever the failure counter says.
/// Catches a probe blocked on a frozen backend (the tick never completes, so
/// the counter never advances) and a wedged probe thread.
inline constexpr std::chrono::milliseconds kStaleAfter{15000};

/// libpq < 17's blocking connect keeps `connect_timeout` as a whole-second
/// wall-clock finish time and re-derives each socket wait from it in whole
/// seconds (`pqSocketPoll`: (finish - time(NULL)) * 1000 ms, 0 once due). The
/// probe waits the same way so it gives up on a host address when the
/// pool's connect does (Gate 8 round 7).
constexpr std::int64_t libpq_wall_wait_seconds(std::int64_t finish_wall_s,
                                               std::int64_t now_wall_s) noexcept {
    return finish_wall_s > now_wall_s ? finish_wall_s - now_wall_s : 0;
}

/// Sentinel for "no probe has ever succeeded".
// Parenthesised so a windows.h min() macro can never expand it (#4722 class).
inline constexpr std::int64_t kNever = (std::numeric_limits<std::int64_t>::min)();

/// What the most recent failed probe saw.
enum class FailureKind : std::uint8_t {
    None,        ///< the most recent probe succeeded
    Unreachable, ///< connect/query failed or timed out
    ReadOnly,    ///< reached a server that refuses writes (a standby, or read-only)
};

/// The probe's published state, as `/readyz` and `/metrics` read it (copied
/// whole under the probe's leaf mutex, so the three fields are always from the
/// same publication).
struct Snapshot {
    std::int64_t last_success_ns{kNever}; ///< steady_clock ns of the last success
    int consecutive_failures{0};
    FailureKind last_failure{FailureKind::None};
};

enum class Verdict : std::uint8_t {
    Ready,
    NotYetProbed, ///< no probe has completed yet
    Unreachable,  ///< kFailThreshold consecutive connect/query failures
    ReadOnly,     ///< the most recent probe reached a server that refuses writes
    Stale,        ///< no success within kStaleAfter (probe blocked or wedged)
};

/// The readiness rule. `now_ns` is steady_clock ns since its epoch.
///
/// Order matters:
///   1. ReadOnly is IMMEDIATE (one observation). A replica pointed at a standby (or
///      at a primary with `default_transaction_read_only` on) cannot serve
///      writes this instant, and core is the sole `yuzu` writer
///      — there is no read-only degraded mode (durable sessions write through
///      on validate; audit-on-read fails closed).
///   2. Never succeeded: not-ready either way, but name the reason honestly.
///   3. kFailThreshold consecutive failures ⇒ Unreachable.
///   4. No success within kStaleAfter ⇒ Stale.
constexpr Verdict classify(const Snapshot& s, std::int64_t now_ns) noexcept {
    if (s.consecutive_failures >= 1 && s.last_failure == FailureKind::ReadOnly)
        return Verdict::ReadOnly;
    if (s.last_success_ns == kNever)
        return s.consecutive_failures == 0 ? Verdict::NotYetProbed : Verdict::Unreachable;
    if (s.consecutive_failures >= kFailThreshold)
        return Verdict::Unreachable;
    const std::int64_t stale_ns =
        std::chrono::duration_cast<std::chrono::nanoseconds>(kStaleAfter).count();
    // `now_ns < last_success_ns` cannot happen on a steady clock; guard anyway
    // so a caller passing a stale `now` reads Ready rather than overflowing.
    if (now_ns > s.last_success_ns && now_ns - s.last_success_ns > stale_ns)
        return Verdict::Stale;
    return Verdict::Ready;
}

/// Stable, low-cardinality token for the `/readyz` body and logs. Carries no
/// host, DSN or libpq error text — `/readyz` is unauthenticated.
constexpr const char* reason(Verdict v) noexcept {
    switch (v) {
    case Verdict::Ready:
        return "ok";
    case Verdict::NotYetProbed:
        return "not_yet_probed";
    case Verdict::Unreachable:
        return "unreachable";
    case Verdict::ReadOnly:
        return "read_only";
    case Verdict::Stale:
        return "stale";
    }
    return "unknown";
}

} // namespace yuzu::server::pg_reachability
