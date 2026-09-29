#pragma once

/**
 * tar_usage.hpp -- pure process-event pairing fold for the TAR `usage` source
 * (machine-scope app-usage aggregate), plus the fold's lifecycle contract.
 *
 * Architect decision: `usage` is a DERIVED FOLD over process_live on the fast
 * tick, NOT a CursorSource. Its persisted state is a high-water mark over
 * process_live.id plus an open-run table (usage_live) -- both advanced
 * transactionally by run_usage_fold() (tar_usage.cpp). This header is the
 * PURE half: no SQLite, no clock reads -- every function takes `now`
 * injected, matching tar_cursor.hpp's own now-injection shape, so the
 * pairing logic is fully exercised by test_tar_usage.cpp against fixture
 * ProcessEvent sequences with no DB and no wall clock.
 *
 * DRAIN ARITHMETIC (why the gap check in tar_usage.cpp is load-bearing):
 * the fast tick runs every 60s (tar_plugin.cpp kFastIntervalDefault) and
 * run_usage_fold caps itself at max_events_per_tick=20000 rows/tick, i.e.
 * ~333 events/s sustained before the fold starts trailing the write rate.
 * process_live holds up to 100k rows (kRowCount, tar_schema_registry.cpp);
 * its row-cap prune runs on the rollup cadence and deletes at most 5000 of
 * the LOWEST ids per pass (tar_aggregator.cpp run_retention). So a fold that
 * falls behind by more than the prune's per-pass headroom can find its next
 * unprocessed id already gone -- that is a genuine capture gap, and
 * tar_usage.cpp's MIN(id) check against the persisted high-water mark is the
 * honesty backstop for exactly that tail: it turns a silent skip into a
 * counted, reported loss (usage_gap_count / usage_gap_lost_events) rather
 * than an unnoticed hole in usage_daily.
 *
 * LIFECYCLE (Wave 7 PR7.2b redo -- replaces marker-existence with an explicit
 * state derived from three persisted facts, never written at boot/configure
 * time and never gated on the mere presence of a marker):
 *
 *   Disabled       -- `usage_enabled` is not "true" (canonical tri-state).
 *   PendingBaseline -- enabled, but `usage_active_generation` does not match
 *                      the current `usage_generation` (including: neither
 *                      has ever been written, or a read of either failed --
 *                      both fail TOWARD re-baselining, never toward Active).
 *   Active         -- enabled AND the two generations match: the fold's
 *                      cursor/open-run state was established under the
 *                      CURRENT activation period, not a stale one.
 *
 * `usage_generation` is bumped -- atomically, alongside the enabled flag --
 * on EVERY enable/disable edge (usage_set_enabled, tar_usage.cpp), so a
 * disable-then-re-enable always lands in PendingBaseline even if some other
 * code path never explicitly invalidates anything: the generation the LAST
 * successful baseline stamped can never match a NEWER one. This is what
 * makes "forward-only, no retrospective backfill across a disabled window"
 * (docs/user-manual/tar.md) a property of the STATE MACHINE rather than of
 * three independent marker-writing call sites (boot, configure, fast-tick)
 * each remembering to get it right -- exactly the shape that let the
 * original PR's boot-time rebaseline ignore `usage_enabled` entirely and
 * stamp a coverage marker even while disabled, so a later failed enable-edge
 * rebaseline replayed the whole disabled window forward from a stale marker.
 * `usage_ensure_baselined()` is the ONE function boot, configure, and every
 * fast tick all call to reconcile this state; none of them writes a marker
 * directly.
 *
 * exe_key normalisation: lowercase, basename after the last '/' or '\\',
 * trimmed of surrounding whitespace, empty -> "(unknown)". Windows keeps the
 * `.exe` suffix (never stripped). Linux `comm` (the `name` field ProcessEvent
 * carries for the process source) is already 15-char truncated by the kernel
 * before it ever reaches this function -- this function does not itself
 * truncate, so two Linux binaries whose names collide in the first 15 bytes
 * alias to the same exe_key; that is a kernel-imposed limit, not a defect
 * here. THIS FUNCTION IS THE SOURCE OF TRUTH for the rule: the forthcoming
 * `app_usage` plugin's app_usage_parsers.hpp (agents/plugins/app_usage/src/,
 * not yet landed) is planned to duplicate it byte-for-byte, since that
 * plugin cannot depend on tar's internal headers -- when it lands, its own
 * parity test should pin the duplication, and any change here must be
 * mirrored there by hand.
 */

#include "tar_db.hpp" // yuzu::tar::ProcessEvent

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <expected>
#include <limits>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::tar::usage {

/// Lowercase, basename after the last '/' or '\\', trimmed, empty ->
/// "(unknown)". See the file banner for the Windows/.exe and Linux/comm
/// notes. Planned to be mirrored byte-for-byte in the forthcoming
/// agents/plugins/app_usage/src/app_usage_parsers.hpp (not yet landed) --
/// this is the source of truth for the rule.
[[nodiscard]] inline std::string normalise_exe_key(std::string_view raw) {
    std::string s{raw};
    if (const auto pos = s.find_last_of("/\\"); pos != std::string::npos)
        s = s.substr(pos + 1);
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front())))
        s.erase(s.begin());
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back())))
        s.pop_back();
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (s.empty())
        return "(unknown)";
    return s;
}

/// An in-progress (pid, exe_key) run, not yet closed by a "stopped" event.
struct OpenRun {
    uint32_t pid{0};
    std::string exe_key;
    std::string user;
    int64_t start_ts{0};
};

/// A run that has ended, one way or another -- `kind` says why.
struct ClosedRun {
    enum class Kind {
        normal,     ///< closed by a matching "stopped" event
        superseded, ///< a NEW "started" for the same (pid, exe_key) arrived
                    ///< before this one's "stopped" -- pid reuse or a missed
                    ///< stop event; the old run is closed at the new start_ts
        expired,    ///< never closed; aged out past expire_open_runs' max_age
        capped,     ///< never closed; evicted by cap_open_runs to bound the
                    ///< open set (oldest start_ts first)
    };
    uint32_t pid{0}; // REQUIRED -- usage_live's unique key is (pid, exe_key)
                     // and the fold deletes closed rows by it.
    std::string exe_key;
    std::string user;
    int64_t start_ts{0};
    int64_t end_ts{0};
    Kind kind{Kind::normal};
};

/// In-memory fold state carried between ticks: the open-run table (mirrors
/// usage_live) plus two machine-scope counters that are NOT attributable to
/// any single exe_key (they live in tar_config, never as usage_daily
/// columns -- see tar_usage.cpp banner).
///
/// `open_by_start_ts` is a secondary index over `open`, ordered by
/// `start_ts`, kept in lockstep SOLELY through insert_open_run()/
/// erase_open_run() below -- never mutate `open` directly. It exists so
/// cap_open_runs() can evict the globally oldest run in O(log N) rather than
/// a full O(N) linear scan per eviction (issue #4253): once the fold commits
/// open-run changes inside the SAME checked_transaction as everything else
/// (tar_usage.cpp), that scan's cost is `mu_` LOCK-HOLD time blocking the
/// collection feeder and the retention thread, not idle CPU.
struct FoldState {
    std::map<std::pair<uint32_t, std::string>, OpenRun> open;
    std::multimap<int64_t, std::pair<uint32_t, std::string>> open_by_start_ts;
    int64_t unmatched_stops{0};
    int64_t clock_anomalies{0};
};

/// The only sanctioned way to add an open run -- keeps `open` and
/// `open_by_start_ts` in lockstep. `key` must not already be present (every
/// call site erases first via erase_open_run() when superseding).
inline void insert_open_run(FoldState& state, std::pair<uint32_t, std::string> key, OpenRun run) {
    state.open_by_start_ts.emplace(run.start_ts, key);
    state.open.emplace(std::move(key), std::move(run));
}

/// The only sanctioned way to remove an open run, by iterator into `open`.
/// Invalidates `it`; any OTHER iterator into `open` (e.g. one already
/// advanced past `it` by the caller's own loop) remains valid -- `std::map`
/// is node-based.
inline void erase_open_run(FoldState& state,
                           std::map<std::pair<uint32_t, std::string>, OpenRun>::iterator it) {
    auto [lo, hi] = state.open_by_start_ts.equal_range(it->second.start_ts);
    for (auto oit = lo; oit != hi; ++oit) {
        if (oit->second == it->first) {
            state.open_by_start_ts.erase(oit);
            break;
        }
    }
    state.open.erase(it);
}

constexpr int64_t kDefaultMaxAgeSeconds = 604800; // 7 days
constexpr size_t kMaxOpenRuns = 20000;

/// `a - b`, saturating at the int64 range boundary instead of invoking UB on
/// overflow. Adversarial review (Wave 7 PR7.2): `now - start_ts` in
/// expire_open_runs overflows when `start_ts` is an extreme value (e.g.
/// INT64_MIN from a corrupt/adversarial process_live row) and `now` is a
/// plausible epoch second -- reproduced under UBSan. Every caller here only
/// ever compares the result against a small positive `max_age`, so
/// saturating (rather than, say, throwing) is the right degrade: a
/// saturated-to-max result still correctly reads as "older than max_age".
[[nodiscard]] constexpr int64_t saturating_sub(int64_t a, int64_t b) noexcept {
    if (b > 0 && a < std::numeric_limits<int64_t>::min() + b)
        return std::numeric_limits<int64_t>::min();
    if (b < 0 && a > std::numeric_limits<int64_t>::max() + b)
        return std::numeric_limits<int64_t>::max();
    return a - b;
}

/// `a + b` for two values a caller guarantees are non-negative (fold_daily's
/// durations and its accumulating total_seconds never go negative), saturating
/// at INT64_MAX instead of invoking UB on overflow. governance Gate 3
/// cpp-expert finding: a single saturating_sub on the duration only protects
/// the FIRST extreme value in a bucket -- a SECOND extreme value accumulating
/// into an already-large total_seconds can overflow the `+=` itself even
/// though neither operand alone was out of range at the point it was computed.
/// Self-defending (governance Gate 8 cpp-safety re-review): `INT64_MAX - b`
/// is itself UB for a negative `b`, so this checks both directions via
/// subtraction rather than trusting the "nonneg" contract at the call site --
/// the name documents intended usage, the implementation doesn't require it.
[[nodiscard]] constexpr int64_t saturating_add_nonneg(int64_t a, int64_t b) noexcept {
    if (b > 0 && a > std::numeric_limits<int64_t>::max() - b)
        return std::numeric_limits<int64_t>::max();
    if (b < 0 && a < std::numeric_limits<int64_t>::min() - b)
        return std::numeric_limits<int64_t>::min();
    return a + b;
}

/// Floor-toward-negative-infinity bucketing of `ts` into a UTC day boundary,
/// without ever negating `ts` directly -- negating INT64_MIN overflows
/// (adversarial review, Wave 7 PR7.2), which the previous
/// `-(((-ts) + 86399) / 86400) * 86400` formula did for exactly that input.
/// Shared by fold_daily() below and tar_usage.cpp's usage_daily_user
/// bucketing so both use the SAME, overflow-safe rule.
[[nodiscard]] constexpr int64_t day_ts_for(int64_t ts) noexcept {
    constexpr int64_t kDay = 86400;
    if (ts >= 0)
        return (ts / kDay) * kDay;
    // Guard the one region where the floor-adjusted bucket boundary would
    // itself be mathematically below INT64_MIN: INT64_MIN is not a multiple
    // of kDay, so its TRUE floor boundary is one day further negative than
    // int64 can represent. `ts` within one day-width of INT64_MIN hits
    // this; saturate to the smallest representable day-aligned bucket
    // rather than compute an unrepresentable value. An input this extreme
    // is already corrupt/adversarial, not a real epoch second.
    constexpr int64_t kMin = std::numeric_limits<int64_t>::min();
    if (ts <= kMin + kDay)
        return (kMin / kDay) * kDay;
    const int64_t q = ts / kDay; // truncates toward zero
    const int64_t r = ts % kDay;
    return (r == 0) ? q * kDay : (q - 1) * kDay;
}

/**
 * Apply one process event to the fold.
 *
 * "started": if an open run already exists for (pid, exe_key) -- pid reuse,
 * or a missed "stopped" -- it is closed `superseded` at end_ts = this
 * event's start_ts, and returned; the new run then opens. Otherwise nothing
 * closes and nullopt is returned.
 *
 * "stopped": pops the open run for (pid, exe_key), if any, and closes it
 * `normal` at this event's ts. Duration is clamped >= 0: if ts < start_ts
 * (a clock step backwards) end_ts is set to start_ts (0s duration) and
 * `clock_anomalies` is incremented. No matching open run -> `unmatched_stops`
 * increments and nullopt is returned -- there is nothing to close.
 *
 * Any other `action` value is ignored (returns nullopt, no state change) --
 * process_live's action column is "started"/"stopped" only, so this is
 * defensive, not a documented input.
 */
[[nodiscard]] inline std::optional<ClosedRun> apply_event(FoldState& state,
                                                          const ProcessEvent& ev) {
    const auto exe_key = normalise_exe_key(ev.name);
    const auto key = std::make_pair(ev.pid, exe_key);

    if (ev.action == "started") {
        std::optional<ClosedRun> superseded;
        if (auto it = state.open.find(key); it != state.open.end()) {
            ClosedRun closed;
            closed.pid = it->second.pid;
            closed.exe_key = it->second.exe_key;
            closed.user = it->second.user;
            closed.start_ts = it->second.start_ts;
            // Same clamp the "stopped" path below applies (adversarial
            // review, Wave 7 PR7.2): a backward clock step between this
            // run's start and the new "started" that supersedes it must not
            // produce a negative duration -- reproduced with
            // duration=-1000 and clock_anomalies never incremented before
            // this fix.
            if (ev.ts < closed.start_ts) {
                closed.end_ts = closed.start_ts; // clamp to 0s duration
                ++state.clock_anomalies;
            } else {
                closed.end_ts = ev.ts;
            }
            closed.kind = ClosedRun::Kind::superseded;
            superseded = closed;
            erase_open_run(state, it);
        }
        OpenRun run;
        run.pid = ev.pid;
        run.exe_key = exe_key;
        run.user = ev.user;
        run.start_ts = ev.ts;
        insert_open_run(state, key, std::move(run));
        return superseded;
    }

    if (ev.action == "stopped") {
        auto it = state.open.find(key);
        if (it == state.open.end()) {
            ++state.unmatched_stops;
            return std::nullopt;
        }
        ClosedRun closed;
        closed.pid = it->second.pid;
        closed.exe_key = it->second.exe_key;
        closed.user = it->second.user;
        closed.start_ts = it->second.start_ts;
        if (ev.ts < closed.start_ts) {
            closed.end_ts = closed.start_ts; // clamp to 0s duration
            ++state.clock_anomalies;
        } else {
            closed.end_ts = ev.ts;
        }
        closed.kind = ClosedRun::Kind::normal;
        erase_open_run(state, it);
        return closed;
    }

    return std::nullopt;
}

/// Close every open run older than `max_age` seconds as `expired`, end_ts =
/// start_ts (0s -- never fabricate a duration for a run whose stop was never
/// observed).
[[nodiscard]] inline std::vector<ClosedRun>
expire_open_runs(FoldState& state, int64_t now, int64_t max_age = kDefaultMaxAgeSeconds) {
    std::vector<ClosedRun> closed;
    for (auto it = state.open.begin(); it != state.open.end();) {
        if (saturating_sub(now, it->second.start_ts) > max_age) {
            ClosedRun c;
            c.pid = it->second.pid;
            c.exe_key = it->second.exe_key;
            c.user = it->second.user;
            c.start_ts = it->second.start_ts;
            c.end_ts = it->second.start_ts;
            c.kind = ClosedRun::Kind::expired;
            closed.push_back(std::move(c));
            auto next = std::next(it);
            erase_open_run(state, it);
            it = next;
        } else {
            ++it;
        }
    }
    return closed;
}

/// Bound the open set: while it exceeds `max_open`, close the OLDEST run (by
/// start_ts) as `capped` (0s -- never fabricated), so the open set is bounded
/// by the FOLD itself, not by the generic row-count prune. O(log N) per
/// eviction via `open_by_start_ts` (issue #4253 -- was a full O(N) linear
/// scan of `open` per eviction).
[[nodiscard]] inline std::vector<ClosedRun> cap_open_runs(FoldState& state,
                                                          size_t max_open = kMaxOpenRuns) {
    std::vector<ClosedRun> closed;
    while (state.open.size() > max_open) {
        auto oldest = state.open_by_start_ts.begin();
        auto it = state.open.find(oldest->second);
        ClosedRun c;
        c.pid = it->second.pid;
        c.exe_key = it->second.exe_key;
        c.user = it->second.user;
        c.start_ts = it->second.start_ts;
        c.end_ts = it->second.start_ts;
        c.kind = ClosedRun::Kind::capped;
        closed.push_back(std::move(c));
        erase_open_run(state, it);
    }
    return closed;
}

/// One (day_ts, exe_key) aggregation delta, ready to upsert into usage_daily.
/// `expired_runs` counts BOTH `expired` and `capped` closures -- neither ever
/// observed a real stop, so they share a bucket distinct from `normal` and
/// `superseded`. user/pid are deliberately absent: usage_daily never carries
/// per-user or per-process identity (that lives in usage_daily_user / the
/// deleted usage_live rows only).
struct DailyDelta {
    int64_t day_ts{0};
    std::string exe_key;
    int64_t run_count{0};
    int64_t total_seconds{0};
    int64_t first_seen{0};
    int64_t last_seen{0};
    int64_t superseded_runs{0};
    int64_t expired_runs{0};
};

/// Attribute each closed run to the UTC day of its START (documented: a run
/// spanning midnight is booked entirely on the day it began, never split).
/// Aggregates by (day_ts, exe_key) across the whole input vector.
[[nodiscard]] inline std::vector<DailyDelta> fold_daily(const std::vector<ClosedRun>& runs) {
    std::map<std::pair<int64_t, std::string>, DailyDelta> acc;
    for (const auto& r : runs) {
        const int64_t day_ts = day_ts_for(r.start_ts);
        auto key = std::make_pair(day_ts, r.exe_key);
        auto [it, inserted] = acc.try_emplace(key);
        DailyDelta& d = it->second;
        if (inserted) {
            d.day_ts = day_ts;
            d.exe_key = r.exe_key;
            d.first_seen = r.start_ts;
            d.last_seen = r.start_ts;
        }
        // Non-negative by apply_event's clamp, but NOT representability-safe:
        // an extreme start_ts (e.g. INT64_MIN from a corrupt process_live
        // row) still overflows a plain subtraction (governance Gate 3
        // cpp-expert finding -- this file's own saturating_sub was added for
        // exactly this threat model and missed this call site). The
        // accumulator needs its own saturating add too, since a second
        // extreme value in the same (day_ts, exe_key) bucket can re-overflow
        // even after the first one already saturated.
        const int64_t duration = saturating_sub(r.end_ts, r.start_ts);
        ++d.run_count;
        d.total_seconds = saturating_add_nonneg(d.total_seconds, duration);
        d.first_seen = std::min(d.first_seen, r.start_ts);
        d.last_seen = std::max(d.last_seen, r.start_ts);
        if (r.kind == ClosedRun::Kind::superseded)
            ++d.superseded_runs;
        else if (r.kind == ClosedRun::Kind::expired || r.kind == ClosedRun::Kind::capped)
            ++d.expired_runs;
    }
    std::vector<DailyDelta> out;
    out.reserve(acc.size());
    for (auto& [k, v] : acc)
        out.push_back(std::move(v));
    return out;
}

/// The `usage` source's collection lifecycle -- see the file banner. Derived
/// fresh every call from three persisted facts; never itself persisted.
enum class LifecycleState {
    Disabled,       ///< usage_enabled is not "true"
    PendingBaseline, ///< enabled, but not yet baselined under the CURRENT activation
    Active,         ///< enabled and baselined under the current activation
};

/**
 * Outcome of one run_usage_fold() pass (tar_usage.cpp). `ok == false` means
 * the whole pass ROLLED BACK -- hwm_id is the value BEFORE the attempt (the
 * store's actual persisted hwm is unchanged), and every other field is
 * whatever was computed before the failing step, informational only.
 */
struct UsageFoldResult {
    bool ok{false};
    std::string error;
    int64_t events_seen{0};
    int64_t runs_closed{0};
    int64_t hwm_id{0};
    int64_t lag_events{0};
    bool gap_detected{false};
};

/// Derive the current lifecycle state (see the file banner). Reads three
/// tar_config facts; never writes anything.
[[nodiscard]] LifecycleState usage_lifecycle_state(TarDatabase& db);

/**
 * Atomically apply an enable/disable edge: the `usage_enabled` flag,
 * `usage_paused_at`, and an `usage_generation` bump, all in ONE
 * checked_transaction. This is `usage`'s own path around the generic
 * `apply_source_enabled_transition`'s path (which also commits atomically since
 * #1654; the usage edge additionally bumps the generation) -- a failed persist
 * refuses the transition outright rather than report success while the flag
 * silently did not move. The generation bump happens on EVERY edge (not only
 * enable): it is what forces `usage_lifecycle_state` to read
 * PendingBaseline the instant this source is next enabled, even across a
 * pause during which nothing else touched the baseline.
 */
[[nodiscard]] bool usage_set_enabled(TarDatabase& db, bool enabled, int64_t now);

/**
 * The ONE lifecycle entry point boot, configure (the enable edge, via
 * `apply_source_enabled_transition`), and every fast tick (via
 * `run_usage_fold`) all call to reconcile state -- see the file banner for
 * why unifying these three previously-independent marker-writing call
 * sites into one function is the fix, not a convenience.
 *
 * A no-op (returns {} immediately) unless the state is PendingBaseline.
 * Otherwise attempts ONE checked_transaction: read the current process
 * boundary, clear the open-run table, and persist the matching cursor
 * (usage_hwm_id), coverage time (usage_coverage_since, informational only --
 * lifecycle gating is by generation, not this), and the active generation,
 * all together. On failure NOTHING is written (forward-only guarantee
 * intact; the caller retries) -- unlike the retired `usage_rebaseline`'s
 * predecessor, there is no window where hwm/coverage persist without the
 * generation, or vice versa.
 */
[[nodiscard]] std::expected<void, std::string> usage_ensure_baselined(TarDatabase& db, int64_t now);

/**
 * Read process_live rows since the persisted `usage_hwm_id`, fold them
 * (pairing, expiry, cap) against the open-run table (usage_live), and
 * commit the whole result -- usage_daily/usage_daily_user upsert, usage_live
 * open-set update, and every tar_config counter -- as ONE
 * checked_transaction, INCLUDING the reads that decide it (see tar_usage.cpp
 * for why: the whole point is that no concurrent purge/configure/retention
 * pass can observe or produce a state between this pass's read and its
 * write). Requires the source to be in `LifecycleState::Active` -- if
 * `PendingBaseline`, attempts `usage_ensure_baselined` first and folds
 * nothing this tick either way (a freshly-established baseline has nothing
 * yet to fold forward from).
 */
[[nodiscard]] UsageFoldResult run_usage_fold(TarDatabase& db, int64_t now,
                                             int64_t max_events_per_tick = 20000);

} // namespace yuzu::tar::usage
