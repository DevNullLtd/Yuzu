#pragma once

/// @file leader_metrics.hpp
/// HA WS-11 (#4014): the `yuzu_server_leader_*` metric family -- how an operator
/// SEES the fenced LeaderElector (ADR-2002 §3/§6/§10, `leader_elector.hpp`).
///
/// This header is the SINGLE source of the metric names, HELP text and label
/// sets. `tests/test_leader_alert_metric_names.py` lexes the string literals
/// below and fails if `docs/prometheus/yuzu-alerts.yml`, the promtool cases or
/// `docs/user-manual/metrics.md` reference a name that is not exported here (a
/// rule that parses but names a series that does not exist can never fire).
///
/// WHY SCRAPE-TIME PULL, NOT LOOP PUSH. The election loop is the sole writer of
/// leadership state and can itself be the thing that wedges: a blocking
/// `PQexec` against a frozen-but-ACKing backend measured ~101 s in this tree
/// (`pg_reachability_probe.hpp`), and neither `statement_timeout` nor
/// `tcp_user_timeout` fires there. A value the loop pushed would freeze at its
/// last reading exactly when it matters; a value computed at scrape time keeps
/// moving (`last_ok_age_seconds` GROWS while the loop is wedged). So the
/// /metrics handler takes a lock-free `LeaderElector::Stats` snapshot and this
/// publisher turns it into series. The loop NEVER touches the MetricsRegistry:
/// `MetricsRegistry::counter()` takes a mutex and builds a `std::string` key
/// that can throw `bad_alloc`, which inside the loop's catch blocks would be a
/// `std::terminate` that defeats the loop's own exception guard.
///
/// LOCK-FREE SCRAPE RULE. The publisher takes a `Stats` VALUE, never a
/// `LeaderElector&`, so a scrape path built on it structurally cannot reach the
/// `mu_`-taking `is_open()` (the loop holds `mu_` across blocking libpq calls
/// -- a stalled coordination probe must never stall a /metrics scrape).
///
/// LAYERING. Lives in `server/core/src`, NOT `common/include/`: it takes a
/// `MetricsRegistry` and the elector's `Stats`, so it is not "pure decision code"
/// under the #2549 firewall.

#include "leader_elector.hpp"

#include <yuzu/metrics.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <mutex>

namespace yuzu::server {

// ---- Names (the lexical drift test reads these literals) ----
inline constexpr const char* kLeaderIsLeaderMetric = "yuzu_server_leader_is_leader";
inline constexpr const char* kLeaderEpochMetric = "yuzu_server_leader_epoch";
inline constexpr const char* kLeaderAcquiredMetric = "yuzu_server_leader_acquired_total";
inline constexpr const char* kLeaderAcquireFailuresMetric =
    "yuzu_server_leader_acquire_failures_total";
inline constexpr const char* kLeaderLostMetric = "yuzu_server_leader_lost_total";
inline constexpr const char* kLeaderLastOkAgeMetric = "yuzu_server_leader_last_ok_age_seconds";
inline constexpr const char* kLeaderLoopErrorsMetric = "yuzu_server_leader_loop_errors_total";

/// Register HELP/TYPE and birth every series at 0 so the first event contributes
/// to `increase()` and a "no leader yet" replica reads 0, not absent
/// (docs/observability-conventions.md). Driven from the elector's closed cause
/// arrays so a seed site and an emit site cannot drift.
///
/// DELIBERATELY not seeded: `yuzu_server_leader_last_ok_age_seconds` -- it is
/// ABSENT until the dedicated connection first answers a query (absent-not-zero:
/// a fabricated 0 would read as "answered just now").
///
/// Called only where an elector exists, so a server with no elector exports no
/// leader series at all (never a fabricated "no leader").
///
/// HELP strings are 7-bit ASCII (`scripts/ci/check-metrics-help-ascii.sh`).
inline void seed_leader_metrics(MetricsRegistry& m) {
    m.describe(kLeaderIsLeaderMetric,
               "1 if this replica currently believes it holds server leadership, else 0 "
               "(a belief, not proof; correctness is the epoch fence)",
               "gauge");
    m.describe(kLeaderEpochMetric,
               "Leadership epoch this replica leads at; 0 when it is not leading (NOT the "
               "cluster-wide current epoch)",
               "gauge");
    m.describe(kLeaderAcquiredMetric,
               "Total leadership acquisitions by this process", "counter");
    m.describe(kLeaderAcquireFailuresMetric,
               "Total leadership acquire attempts that failed on infrastructure by cause; "
               "another replica holding the lock is the normal follower outcome and is not counted",
               "counter");
    m.describe(kLeaderLostMetric,
               "Total times held leadership was dropped by cause "
               "(liveness_failed includes every failed heartbeat)",
               "counter");
    m.describe(kLeaderLastOkAgeMetric,
               "Seconds since this replica's dedicated coordination connection last answered a "
               "query; absent until the first success",
               "gauge");
    m.describe(kLeaderLoopErrorsMetric,
               "Total election-loop iterations that threw an exception", "counter");

    m.gauge(kLeaderIsLeaderMetric).set(0);
    m.gauge(kLeaderEpochMetric).set(0);
    (void)m.counter(kLeaderAcquiredMetric);
    for (const char* cause : kAcquireFailureLabels)
        (void)m.counter(kLeaderAcquireFailuresMetric, {{"cause", cause}});
    for (const char* cause : kLeadershipLossLabels)
        (void)m.counter(kLeaderLostMetric, {{"cause", cause}});
    (void)m.counter(kLeaderLoopErrorsMetric);
}

/// Turns a `LeaderElector::Stats` snapshot into series on each /metrics scrape.
class LeaderMetricsPublisher {
public:
    /// Monotonic "now" in the SAME clock/units as `Stats::last_ok_steady_ns`.
    /// Delegates to the elector so the stamp and the age read ONE clock/unit.
    [[nodiscard]] static std::int64_t steady_now_ns() noexcept {
        return LeaderElector::steady_now_ns();
    }

    /// Sets the gauges and syncs the counters. `loop_errors` is the monotonic
    /// tally the election loop keeps in a plain atomic (it never touches `m`).
    ///
    /// Counters are synced by DELTA (`Counter` has no `set()`): increment the
    /// exported series by `stat - value()` when positive. The whole body is
    /// serialized so two CONCURRENT scrapes (an HA Prometheus pair) cannot both
    /// read the same `value()`, compute the same delta and double-increment --
    /// the NVD precedent (`health_routes.cpp`, #1909).
    void publish(MetricsRegistry& m, const LeaderElector::Stats& s, std::uint64_t loop_errors,
                 std::int64_t now_steady_ns) {
        std::lock_guard<std::mutex> lk(mu_);
        m.gauge(kLeaderIsLeaderMetric).set(s.leader ? 1 : 0);
        // Absent-vs-0 is unambiguous only because minted epochs are >= 1 (see
        // LeaderElector::try_acquire): 0 always means "not leading".
        m.gauge(kLeaderEpochMetric).set(s.leader ? static_cast<double>(s.epoch) : 0);
        sync(m.counter(kLeaderAcquiredMetric), s.acquired);
        for (std::size_t i = 0; i < kAcquireFailureCount; ++i)
            sync(m.counter(kLeaderAcquireFailuresMetric, {{"cause", kAcquireFailureLabels[i]}}),
                 s.acquire_failed[i]);
        for (std::size_t i = 0; i < kLeadershipLossCount; ++i)
            sync(m.counter(kLeaderLostMetric, {{"cause", kLeadershipLossLabels[i]}}), s.lost[i]);
        sync(m.counter(kLeaderLoopErrorsMetric), loop_errors);
        // Absent until the first success; computed here so it keeps GROWING while
        // the election loop is wedged. Clamped at 0 against a reordered clock read.
        if (s.last_ok_steady_ns != 0) {
            const std::int64_t age_ns = now_steady_ns - s.last_ok_steady_ns;
            m.gauge(kLeaderLastOkAgeMetric).set(age_ns > 0 ? static_cast<double>(age_ns) / 1e9 : 0);
        }
    }

private:
    static void sync(Counter& c, std::uint64_t target) {
        const double delta = static_cast<double>(target) - c.value();
        if (delta > 0)
            c.increment(delta);
    }

    std::mutex mu_;
};

} // namespace yuzu::server
