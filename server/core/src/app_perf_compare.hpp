#pragma once

/// @file app_perf_compare.hpp
/// PURE engine for the `/auto` VERIFY stage — the cohort-PAIRED before/after
/// app-performance comparison (UAT non-functional evidence). Reduces the shipped
/// B1 per-device daily store (`app_perf_daily_store`) to a per-machine
/// before-vs-after delta, then aggregates the deltas. No PG, no I/O — the impure
/// cohort read lives in `app_perf_cohort_reader.{hpp,cpp}`, the surfaces in
/// `verify_routes`/REST/MCP. Kept pure + here so the three surfaces render the
/// SAME numbers (same reason `dex_app_perf_model.hpp` exists for the fleet trend).
///
/// ── Two load-bearing design choices (locked 2026-06-30) ──
///
/// **Cohort-paired, not fleet-aggregate.** The delta is computed PER MACHINE
/// (this device's own baseline-version window vs its own candidate-version window),
/// then aggregated. A fleet-vBaseline-vs-fleet-vCandidate diff is confounded — the
/// machines on each version are different populations — so a shift there conflates
/// "the build is heavier" with "a different crowd upgraded". Pairing on `agent_id`
/// holds the population fixed; a machine that ran only one of the two versions
/// in-window is EXCLUDED and counted, never imputed.
///
/// **The window is per-machine-per-version, anchored to that machine's version
/// transition — NOT a global `[today - window, today]` cut.** B1 is keyed
/// `(agent, version, day)` at 31-day retention; a machine that upgraded more than
/// `window_days` ago has its baseline-version days OUTSIDE a today-anchored window,
/// so it would read as unpaired and a staggered rollout would render an empty
/// panel. "N days each side" means the most recent N days the machine ran the
/// baseline and the most recent N it ran the candidate, each anchored to its own
/// days. `today` only bounds the 31-day horizon upstream (the store prunes there).
///
/// ── Evidential, not judgmental ──
/// There is NO verdict here — no pass/fail, no threshold, no "regressed" flag.
/// The engine reports the measured shift + the per-machine spread; the operator
/// (or the AI colleague over MCP) judges. Small cohorts are NOT suppressed (real
/// canaries are 2–3 devices — a floor would gut the feature); a sub-`kDexCohortFloor`
/// paired set is flagged `small_cohort` so the surface can mark it "indicative".
///
/// ── The candidate-source seam ──
/// `reduce_version_window` turns B1 rows into per-machine scalars; `compare` pairs
/// two scalar sets. Slice 2's LIVE candidate (fan-out procperf right after deploy)
/// produces `MachineVersionScalar`s its own way and feeds the SAME `compare` — the
/// engine never forks on where the candidate came from. (Slice-2 note: normalize
/// the live CPU unit to B1's `cpu_avg` = share-of-machine-capacity % in that
/// producer, or the paired delta is meaningless.)

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server {

/// Max length of an operator-supplied app/version/group identifier across every
/// app-perf surface (REST, MCP, dashboard) — one cap so the surfaces agree.
/// Relocated here from `dex_app_perf_model.hpp` (ADR-0031 WS-A4 #4250) — it is
/// PURE and belongs in the store-free header every app-perf-adjacent TU
/// (including the VERIFY seam's `verify_routes.cpp`) can safely reach;
/// `dex_app_perf_model.hpp` still re-exposes it transitively via its own
/// `#include "app_perf_compare.hpp"`, so no existing caller's include changes.
inline constexpr std::size_t kAppPerfParamCap = 512;

/// PURE: validate an operator-supplied app/version/group identifier before it
/// reaches a store binding. Rejects oversize (> `kAppPerfParamCap`) or any C0
/// control byte INCLUDING NUL — a NUL truncates a libpq text parameter, so the
/// store would silently query a DIFFERENT key than supplied (a cross-surface
/// semantic divergence, not injection — everything is bound). Does NOT reject
/// empty: `version=""` is the all-versions sentinel; callers reject an empty
/// `app`/`group_id` themselves. The ONE validator the three surfaces share so they
/// cannot drift on the accepted charset/cap.
[[nodiscard]] bool app_perf_param_valid(std::string_view s);

/// One B1 daily row with `agent_id` PRESERVED — what the cohort reader returns.
/// (`AppPerfDailyRow` drops the id because its APIs are per-agent; pairing needs
/// it, so this is a distinct shape.) `version` is the canon quad ("" = unknown);
/// `cpu_avg` is share-of-machine-capacity percent, `ws_avg_bytes` is bytes.
struct AppPerfCohortRow {
    std::string agent_id;
    std::string version;
    std::int64_t day{0}; ///< UTC midnight epoch seconds
    std::int64_t samples{0};
    double cpu_avg{0.0};
    std::int64_t ws_avg_bytes{0};
};

/// One machine reduced to a single window scalar for ONE version — THE seam the
/// live candidate also produces.
struct MachineVersionScalar {
    std::string agent_id;
    double cpu{0.0};           ///< sample-weighted window mean of `cpu_avg`
    std::int64_t ws{0};        ///< sample-weighted window mean of `ws_avg_bytes`
    std::int64_t samples{0};   ///< total samples across the window's days
    std::int64_t day_count{0}; ///< distinct days of this version in the window
};

/// PURE: reduce cohort B1 rows to one scalar per machine for `version`, using the
/// per-machine-per-version window (the most recent `window_days` distinct days
/// THIS machine ran `version` — see the file header on why this is not
/// today-anchored). Sample-weighted mean (`Σ value·samples / Σ samples`). A machine
/// whose entire in-window history for the version has ZERO samples measured nothing,
/// so it produces NO scalar and is EXCLUDED — it is NOT given an unweighted-fallback
/// vote (without a cohort floor that would let one zero-sample canary swing the
/// median; gov UP-3). `version` is matched as supplied — the caller canonicalizes it
/// (and the stored rows) so the keys agree. A machine with no in-window rows of
/// `version` (or only zero-sample rows) is omitted (→ unpaired in `compare`).
/// `window_days <= 0` is treated as 1.
[[nodiscard]] std::vector<MachineVersionScalar>
reduce_version_window(const std::vector<AppPerfCohortRow>& rows, std::string_view version,
                      int window_days);

/// One machine's before→after pair — the row the audited per-machine drill shows.
struct MachinePair {
    std::string agent_id;
    double cpu_before{0.0};
    double cpu_after{0.0};
    double cpu_delta{0.0}; ///< after − before (percentage points)
    std::int64_t ws_before{0};
    std::int64_t ws_after{0};
    std::int64_t ws_delta{0}; ///< after − before (bytes)
    /// The weaker side's sample count (`min(before, after)`) — it bounds how much
    /// confidence the pair carries; a 3-sample side makes the delta noisy.
    std::int64_t samples{0};
};

/// The aggregated cohort-paired comparison. NO verdict — the measured shift only.
/// Aggregates are over the PAIRED set; each machine contributes one scalar, so the
/// percentiles are exact (no histogram needed, unlike the fleet B2 path).
struct PairedComparison {
    std::string baseline_version;
    std::string candidate_version;
    int window_days{0};

    std::int64_t paired{0};         ///< machines present in BOTH versions in-window
    std::int64_t baseline_only{0};  ///< ran baseline but not candidate in-window (excluded)
    std::int64_t candidate_only{0}; ///< ran candidate but not baseline (excluded)

    double cpu_before_mean{0.0};
    double cpu_after_mean{0.0};
    double cpu_delta_median{0.0}; ///< median per-machine Δ — the headline quantity
    double cpu_before_p95{0.0};
    double cpu_after_p95{0.0};
    std::int64_t ws_before_mean{0};
    std::int64_t ws_after_mean{0};
    std::int64_t ws_delta_median{0};
    std::int64_t ws_before_p95{0};
    std::int64_t ws_after_p95{0};

    /// CPU per-machine direction split (band `kCpuFlatBandPp`).
    std::int64_t moved_up{0};
    std::int64_t moved_flat{0};
    std::int64_t moved_down{0};

    /// `paired` is non-zero but below `kDexCohortFloor` — NOT suppressed (canaries
    /// are small by design); the surface marks the aggregate "indicative".
    bool small_cohort{false};
    /// `paired == 0` — no machine ran both versions in-window; nothing to compare.
    bool insufficient{false};

    /// Per-machine pairs for the AUDITED drill, sorted by descending CPU delta
    /// (largest mover first — a factual ordering, never a "worst/regressed" label).
    std::vector<MachinePair> pairs;
};

/// The CPU "flat" band in percentage points: `|Δ| <= this` counts as unchanged.
inline constexpr double kCpuFlatBandPp = 0.3;

/// PURE: pair `baseline` and `candidate` scalars by `agent_id`, compute per-machine
/// deltas, and aggregate. The ONE place the comparison math lives so dashboard,
/// REST and MCP cannot disagree. No floor, no verdict. Percentiles use the
/// platform nearest-rank direction (`r = ceil(p·n)`), matching `detail::nearest_rank`
/// / `percentile_from_hist`. Inputs may be in any order; a duplicate `agent_id`
/// within one set takes the first occurrence (the reducer already yields one per
/// machine, so this is just defence).
[[nodiscard]] PairedComparison
compare(const std::vector<MachineVersionScalar>& baseline,
        const std::vector<MachineVersionScalar>& candidate, std::string_view baseline_version,
        std::string_view candidate_version, int window_days);

/// PURE: the single assembly the dashboard, REST and MCP all call — reduce both
/// versions' per-machine windows from raw cohort B1 rows, then `compare`. Keeping
/// the two-reduce-then-compare sequence in ONE place is what stops the three
/// surfaces from drifting (the same reason `app_perf_fleet_trend` is one fn).
/// `baseline_version`/`candidate_version` must be canonicalized by the caller to
/// match the stored `rows[*].version` key (the cohort reader canons the rows).
[[nodiscard]] PairedComparison build_comparison(const std::vector<AppPerfCohortRow>& rows,
                                                std::string_view baseline_version,
                                                std::string_view candidate_version, int window_days);

/// PURE: cohort members with NO app-perf data for either version =
/// `member_count - paired - baseline_only - candidate_only`, clamped to >= 0. The
/// ONE place this derived count is computed so REST, MCP and the dashboard agree
/// (it was otherwise re-derived inline at each surface). `member_count` comes from
/// the provider (the group's resolved size), not the engine.
[[nodiscard]] std::int64_t cohort_no_data(const PairedComparison& c, std::int64_t member_count);

} // namespace yuzu::server
