/**
 * tar_usage.cpp -- the SQLite shell for the `usage` derived fold (see
 * tar_usage.hpp for the pure pairing logic, the lifecycle contract, and the
 * drain-arithmetic banner).
 *
 * run_usage_fold() is the ONE entry point tar_plugin.cpp's collect_fast_impl
 * calls, once per fast tick, after both process feeders (gap-free stream or
 * snapshot-diff poll) have inserted for that tick. usage_daily_user's own
 * RETENTION prune is NOT here -- it runs under tar_aggregator.cpp's
 * clock-guarded run_retention instead, as its own independently-reachable
 * target (see docs/clock-guarded-retention.md).
 *
 * CHECKED_TRANSACTION, NOT THE TOLERANT BATCH APIS (Wave 7 PR7.2b redo).
 * Both round 1 and round 2 of this source's adversarial review found the
 * SAME invariant violated through different code paths: a partial commit
 * silently and permanently losing data (round 1 Blocker 1: `execute_atomic_
 * batch`'s data segment can commit with one statement skipped while the
 * HWM upsert in the SAME batch still advances; round 2: the gated variant's
 * DATA segment stayed just as tolerant, so a carried-over run's `usage_live`
 * DELETE could still commit durably even when a sibling daily-upsert
 * failed, permanently destroying that run's only re-derivation state; round
 * 2 also found `usage_rebaseline` never adopted the gated primitive at all
 * and checked only `.committed`, never `.failed[]`). Every fix patched the
 * SPECIFIC reported scenario without hardening the shared primitive, so the
 * next round found a sibling instance. `TarDatabase::checked_transaction`
 * (tar_db.hpp) closes the invariant AT THE PRIMITIVE instead: it commits
 * ALL of a transaction's statements or NONE of them, full stop -- there is
 * no data/gated split to have a residual tolerant half. The fold below, and
 * `usage_ensure_baselined`/`usage_set_enabled`, are its first real callers.
 *
 * This retires the `fold_hwm` replay-guard column and the carried-over/
 * same-tick provenance split the previous shape needed to survive a
 * partial commit: a `checked_transaction` failure leaves hwm/usage_live/
 * usage_daily/usage_daily_user ALL unchanged (nothing durable at all), so
 * the next tick re-reads the identical [hwm, max_id] range and re-derives
 * the identical closed-run deltas -- safe to re-apply via a PLAIN additive
 * upsert, because there is no partially-committed predecessor to double-
 * count on top of. A crash can only land before the transaction's single
 * COMMIT (SQLite's own WAL recovery rolls the whole thing back) or after it
 * (everything durable together, always).
 *
 * READS ARE INSIDE THE TRANSACTION TOO, not just the writes. The gap-check +
 * event read and the open-run-table load both happen via `TransactionHandle
 * ::raw()` inside the SAME checked_transaction as every write this pass
 * produces (see run_usage_fold below) -- `checked_transaction` holds `mu_`
 * for its whole duration, so this is what makes the READ that decides this
 * pass's deltas and the WRITE that commits them one indivisible snapshot: a
 * concurrent `tar.purge_source usage` or an enable/disable edge cannot land
 * in the gap between them and invalidate what was just computed. A `raw()`
 * caller must never call any OTHER `TarDatabase` method that takes `mu_` --
 * see that method's own doc comment -- so every read below is hand-rolled
 * prepare/step against the raw connection, not `db.execute_query()`.
 *
 * GAP CHECK FIRST, before any events are read: process_live is retained by
 * ROW COUNT (kRowCount, 100k rows, tar_schema_registry.cpp), and its prune
 * (tar_aggregator.cpp run_retention) deletes the LOWEST ids, up to 5000 per
 * rollup pass. If this fold's persisted `usage_hwm_id` is now BELOW the
 * table's current MIN(id) - 1, the rows in between were destroyed before the
 * fold ever read them -- a genuine capture gap, not a caught-up state. That
 * is counted (`usage_gap_count`, `usage_gap_lost_events`,
 * `usage_gap_last_ts`) and the hwm is re-baselined to `min_id - 1` in the
 * SAME transaction as everything else this tick produces, so the gap is
 * never a silent skip: any open run whose "stopped" fell inside the lost
 * range simply never gets one and drains through expire_open_runs on a
 * later tick, counted as `expired` there.
 *
 * tar_config keys this file owns (P22/P24 read them, never write them):
 *   usage_hwm_id             -- high-water mark over process_live.id
 *   usage_unmatched_stops    -- cumulative, += per fold
 *   usage_clock_anomalies    -- cumulative, += per fold
 *   usage_lag_events         -- max(0, max_id - new hwm), snapshot as of last fold
 *   usage_last_fold_ts       -- epoch seconds of the last fold attempt (any outcome)
 *   usage_expiry_declined_count -- cumulative count of ticks whose open-run
 *                               expiry sweep declined for clock implausibility
 *   usage_gap_count          -- cumulative count of gap events detected
 *   usage_gap_lost_events    -- cumulative count of events lost to gaps
 *   usage_gap_last_ts        -- epoch seconds of the most recent gap
 *   usage_feeder_enabled     -- "true"/"false", gating snapshot for P22's report
 *   usage_coverage_since     -- epoch seconds the active period has counted from
 *                               (informational -- lifecycle gating is by
 *                               generation, see usage_lifecycle_state, NOT this)
 *   usage_generation         -- bumped on every enable/disable edge (usage_set_enabled)
 *   usage_active_generation  -- the generation the last successful baseline stamped
 */

#include "tar_usage.hpp"

#include "tar_aggregator.hpp" // source_enabled

#include <sqlite3.h>
#include <spdlog/spdlog.h>

#include <charconv>
#include <format>
#include <memory>
#include <set>
#include <utility>

namespace yuzu::tar::usage {

namespace {

// Doubles embedded single quotes -- the only escape SQLite string literals
// need. Every dynamic string value (exe_key, user) that reaches a hand-built
// SQL statement in this file goes through this.
std::string sql_str(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 2);
    out.push_back('\'');
    for (char c : s) {
        if (c == '\'')
            out.push_back('\'');
        out.push_back(c);
    }
    out.push_back('\'');
    return out;
}

int64_t parse_i64(std::string_view s, int64_t def = 0) {
    if (s.empty())
        return def;
    int64_t v = 0;
    auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (ec != std::errc{} || p != s.data() + s.size())
        return def;
    return v;
}

// One usage_daily upsert statement for `d` -- plain additive, no replay
// guard needed (see file banner: checked_transaction makes one unnecessary).
std::string build_daily_upsert(const DailyDelta& d) {
    return std::format(
        "INSERT INTO usage_daily (day_ts, exe_key, run_count, total_seconds, first_seen, "
        "last_seen, distinct_users, superseded_runs, expired_runs) VALUES ({}, {}, {}, {}, {}, "
        "{}, 0, {}, {}) ON CONFLICT(day_ts, exe_key) DO UPDATE SET "
        "run_count = run_count + excluded.run_count, "
        "total_seconds = total_seconds + excluded.total_seconds, "
        "first_seen = MIN(first_seen, excluded.first_seen), "
        "last_seen = MAX(last_seen, excluded.last_seen), "
        "superseded_runs = superseded_runs + excluded.superseded_runs, "
        "expired_runs = expired_runs + excluded.expired_runs",
        d.day_ts, sql_str(d.exe_key), d.run_count, d.total_seconds, d.first_seen, d.last_seen,
        d.superseded_runs, d.expired_runs);
}

// RAII for a raw sqlite3_stmt* obtained via TransactionHandle::raw() --
// distinct from (and not shared with) tar_db.cpp's own file-local StmtPtr,
// which is not exposed through tar_db.hpp.
struct LocalStmtDeleter {
    void operator()(sqlite3_stmt* s) const { sqlite3_finalize(s); }
};
using LocalStmtPtr = std::unique_ptr<sqlite3_stmt, LocalStmtDeleter>;

std::string_view col_text(sqlite3_stmt* stmt, int idx) {
    const auto* txt = reinterpret_cast<const char*>(sqlite3_column_text(stmt, idx));
    return txt ? std::string_view{txt} : std::string_view{};
}

// Best-effort read of a cumulative status counter FROM INSIDE an open
// checked_transaction (via `h.raw()` -- calling `db.get_config()` here would
// try to reacquire `mu_` and deadlock). A probe failure returns 0 rather
// than poisoning the handle: these four counters (unmatched_stops,
// clock_anomalies, gap_count, gap_lost_events) are cumulative,
// informational-only status -- not one of the fold's three core
// invariants -- so under-counting one tick's contribution on a transient
// read fault is the proportionate degrade, not failing the whole fold's
// data commit over a status counter.
int64_t read_config_i64_locked(TransactionHandle& h, std::string_view key) {
    sqlite3_stmt* raw = nullptr;
    if (sqlite3_prepare_v2(h.raw(), "SELECT value FROM tar_config WHERE key = ?", -1, &raw,
                           nullptr) != SQLITE_OK)
        return 0;
    LocalStmtPtr stmt(raw);
    sqlite3_bind_text(stmt.get(), 1, key.data(), static_cast<int>(key.size()), SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) != SQLITE_ROW)
        return 0;
    return parse_i64(col_text(stmt.get(), 0));
}

// Distinguishes a genuinely-absent key (no row -- a real, legitimate state
// the first time a fold ever runs after baseline) from a read/parse FAILURE
// on an existing key. read_config_i64_locked's "0 on any fault" contract
// above is correct ONLY for its four cumulative status counters; it is wrong
// for `usage_last_fold_ts`, which gates whether expire_open_runs may delete
// anything -- collapsing "absent" and "failed" both to 0 let a transient
// read fault read as a legitimate first-fold state and proceed with the
// sweep (adversarial review Wave 7 PR7.2b fix round 1). Does not poison the
// handle: a failed/absent anchor read declines THIS tick's expiry sweep, it
// does not fail the whole fold (matching the existing clock-implausible
// decline below, which also leaves every other write in this transaction
// intact).
std::expected<std::optional<int64_t>, std::string> read_config_i64_strict(TransactionHandle& h,
                                                                          std::string_view key) {
    sqlite3_stmt* raw = nullptr;
    if (sqlite3_prepare_v2(h.raw(), "SELECT value FROM tar_config WHERE key = ?", -1, &raw,
                           nullptr) != SQLITE_OK)
        return std::unexpected(std::string("prepare failed"));
    LocalStmtPtr stmt(raw);
    sqlite3_bind_text(stmt.get(), 1, key.data(), static_cast<int>(key.size()), SQLITE_TRANSIENT);
    const int rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_DONE)
        return std::optional<int64_t>{}; // genuinely absent -- no row, not a fault
    if (rc != SQLITE_ROW)
        return std::unexpected(std::string("step failed"));
    const std::string_view raw_val = col_text(stmt.get(), 0);
    int64_t parsed = 0;
    auto [p, ec] = std::from_chars(raw_val.data(), raw_val.data() + raw_val.size(), parsed);
    if (ec != std::errc{} || p != raw_val.data() + raw_val.size())
        return std::unexpected(std::string("malformed value"));
    return std::optional<int64_t>(parsed);
}

} // namespace

LifecycleState usage_lifecycle_state(TarDatabase& db) {
    if (!source_enabled(db, "usage"))
        return LifecycleState::Disabled;
    const int64_t generation = parse_i64(db.get_config("usage_generation", "0"));
    const auto active_gen_raw = db.try_get_config("usage_active_generation");
    if (!active_gen_raw.has_value() || !active_gen_raw->has_value())
        return LifecycleState::PendingBaseline; // never baselined, or a read fault --
                                                 // fail toward re-baselining, never Active
    const int64_t active_generation = parse_i64(**active_gen_raw);
    return (active_generation == generation) ? LifecycleState::Active
                                             : LifecycleState::PendingBaseline;
}

bool usage_set_enabled(TarDatabase& db, bool enabled, int64_t now) {
    const int64_t next_generation = parse_i64(db.get_config("usage_generation", "0")) + 1;
    auto result = db.checked_transaction(
        [&](TransactionHandle& h) -> std::expected<void, std::string> {
            if (!h.exec(std::format(
                    "INSERT INTO tar_config (key, value) VALUES ('usage_enabled', '{}') "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    enabled ? "true" : "false")))
                return std::unexpected(h.error());
            if (!h.exec(std::format(
                    "INSERT INTO tar_config (key, value) VALUES ('usage_paused_at', '{}') "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    enabled ? "0" : std::to_string(now))))
                return std::unexpected(h.error());
            // Bumped on EVERY edge, not only enable -- see tar_usage.hpp's file
            // banner. This is what forces usage_lifecycle_state to read
            // PendingBaseline the instant the source is next re-enabled, even
            // if nothing else ever explicitly invalidated the prior baseline.
            if (!h.exec(std::format(
                    "INSERT INTO tar_config (key, value) VALUES ('usage_generation', '{}') "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    next_generation)))
                return std::unexpected(h.error());
            return {};
        });
    if (!result.has_value()) {
        spdlog::error("TAR usage: {} transition failed to persist ({}); source remains at its "
                      "previous state",
                      enabled ? "enable" : "disable", result.error());
        return false;
    }
    return true;
}

std::expected<void, std::string> usage_ensure_baselined(TarDatabase& db, int64_t now) {
    if (usage_lifecycle_state(db) != LifecycleState::PendingBaseline)
        return {}; // disabled, or already active under the current generation

    const int64_t generation = parse_i64(db.get_config("usage_generation", "0"));

    auto result = db.checked_transaction(
        [&](TransactionHandle& h) -> std::expected<void, std::string> {
            sqlite3_stmt* raw = nullptr;
            if (sqlite3_prepare_v2(h.raw(), "SELECT COALESCE(MAX(id), 0) FROM process_live", -1,
                                   &raw, nullptr) != SQLITE_OK) {
                h.fail("prepare MAX(id) probe failed");
                return std::unexpected(std::string("prepare MAX(id) probe failed"));
            }
            int64_t hwm = 0;
            {
                LocalStmtPtr stmt(raw);
                // COALESCE(MAX(id), 0) over no WHERE clause always returns
                // exactly one row on success -- any other step outcome can
                // only be a fault (adversarial review Wave 7 PR7.2b fix
                // round 1), never "legitimately no rows", so it must poison
                // rather than silently commit hwm=0 (which would make the
                // NEXT fold read everything since row 1 -- the retrospective
                // -fold defect this primitive exists to close).
                if (sqlite3_step(stmt.get()) != SQLITE_ROW) {
                    h.fail("step MAX(id) probe failed");
                    return std::unexpected(std::string("step MAX(id) probe failed"));
                }
                hwm = sqlite3_column_int64(stmt.get(), 0);
            }

            if (!h.exec("DELETE FROM usage_live"))
                return std::unexpected(h.error());
            if (!h.exec(std::format(
                    "INSERT INTO tar_config (key, value) VALUES ('usage_hwm_id', '{}') "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    hwm)))
                return std::unexpected(h.error());
            if (!h.exec(std::format(
                    "INSERT INTO tar_config (key, value) VALUES ('usage_coverage_since', '{}') "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    now)))
                return std::unexpected(h.error());
            if (!h.exec(std::format(
                    "INSERT INTO tar_config (key, value) VALUES ('usage_active_generation', "
                    "'{}') ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    generation)))
                return std::unexpected(h.error());
            return {};
        });
    if (!result.has_value())
        spdlog::warn("TAR usage: baseline attempt failed ({}); will retry", result.error());
    return result;
}

UsageFoldResult run_usage_fold(TarDatabase& db, int64_t now, int64_t max_events_per_tick) {
    UsageFoldResult result;

    const bool usage_on = source_enabled(db, "usage");
    const bool process_on = source_enabled(db, "process");
    db.set_config("usage_feeder_enabled", (usage_on && process_on) ? "true" : "false");
    if (!usage_on || !process_on) {
        result.ok = true; // nothing to do this tick -- not a failure
        return result;
    }

    if (usage_lifecycle_state(db) != LifecycleState::Active) {
        // PendingBaseline: attempt now. A freshly-established baseline has
        // nothing yet to fold forward from -- report success but fold zero
        // events this tick either way; the NEXT tick reads forward from it.
        if (auto baseline = usage_ensure_baselined(db, now); !baseline.has_value()) {
            result.error = std::format(
                "usage fold: baseline not established ({}); refusing to consume process_live "
                "until one succeeds",
                baseline.error());
            return result; // ok=false, hwm unchanged
        }
        result.ok = true;
        result.hwm_id = parse_i64(db.get_config("usage_hwm_id", "0"));
        return result;
    }

    // Captured from inside the transaction below, trusted only once
    // `checked_transaction` returns success (see TarDatabase::checked_
    // transaction's own doc comment for why this is the sanctioned pattern).
    int64_t hwm = 0; // read strictly below, inside the transaction
    int64_t new_hwm = 0;
    int64_t events_seen = 0;
    int64_t runs_closed = 0;
    int64_t lag_events = 0;
    bool gap_detected = false;

    auto fold_result = db.checked_transaction(
        [&](TransactionHandle& h) -> std::expected<void, std::string> {
            // ── Read usage_hwm_id strictly, INSIDE the transaction (adversarial
            // review Wave 7 PR7.2b fix round 1). Active lifecycle guarantees
            // usage_ensure_baselined already committed this key in the SAME
            // checked_transaction that stamped usage_active_generation -- both
            // succeed together or neither does -- so by the time this function
            // sees Active, a missing/unreadable/malformed usage_hwm_id can only
            // be a fault (corruption, a lost write, tampering), never a
            // legitimate "not baselined yet". The prior code read this via the
            // lossy `db.get_config(...,"0")` BEFORE the transaction even opened,
            // so a transient or malformed read collapsed to hwm=0 and the fold
            // below would consume `id > 0` -- everything since row 1, past the
            // documented forward-only boundary. Poison instead.
            {
                sqlite3_stmt* hwm_raw = nullptr;
                if (sqlite3_prepare_v2(h.raw(),
                                       "SELECT value FROM tar_config WHERE key = 'usage_hwm_id'",
                                       -1, &hwm_raw, nullptr) != SQLITE_OK) {
                    h.fail("prepare usage_hwm_id read failed");
                    return std::unexpected(std::string("prepare usage_hwm_id read failed"));
                }
                LocalStmtPtr hwm_stmt(hwm_raw);
                if (sqlite3_step(hwm_stmt.get()) != SQLITE_ROW) {
                    h.fail("usage_hwm_id missing or unreadable while Active");
                    return std::unexpected(
                        std::string("usage_hwm_id missing or unreadable while Active"));
                }
                const std::string_view raw_val = col_text(hwm_stmt.get(), 0);
                int64_t parsed = 0;
                auto [p, ec] =
                    std::from_chars(raw_val.data(), raw_val.data() + raw_val.size(), parsed);
                if (ec != std::errc{} || p != raw_val.data() + raw_val.size()) {
                    h.fail("usage_hwm_id malformed while Active");
                    return std::unexpected(std::string("usage_hwm_id malformed while Active"));
                }
                hwm = parsed;
            }
            new_hwm = hwm;

            // ── Gap check + event read, in ONE statement (see file banner for
            // why this is inside the transaction, not a separate db.execute_
            // query() call before it) ──
            const std::string sql = std::format(
                "SELECT r.min_id, r.max_id, r.row_count, e.id, e.ts, e.action, e.pid, e.name, "
                "e.user FROM (SELECT COALESCE(MIN(id), 0) AS min_id, COALESCE(MAX(id), 0) AS "
                "max_id, COUNT(*) AS row_count FROM process_live) r LEFT JOIN (SELECT id, ts, "
                "action, pid, name, user FROM process_live WHERE id > {} ORDER BY id LIMIT {}) e "
                "ON 1=1 ORDER BY e.id",
                hwm, max_events_per_tick);
            sqlite3_stmt* raw = nullptr;
            if (sqlite3_prepare_v2(h.raw(), sql.c_str(), -1, &raw, nullptr) != SQLITE_OK) {
                h.fail("prepare gap-check/event query failed");
                return std::unexpected(std::string("prepare gap-check/event query failed"));
            }
            LocalStmtPtr stmt(raw);

            int64_t min_id = 0, max_id = 0, row_count = 0;
            bool first_row = true;
            std::vector<ProcessEvent> events;
            int64_t computed_new_hwm = hwm;
            int rc;
            while ((rc = sqlite3_step(stmt.get())) == SQLITE_ROW) {
                if (first_row) {
                    min_id = sqlite3_column_int64(stmt.get(), 0);
                    max_id = sqlite3_column_int64(stmt.get(), 1);
                    row_count = sqlite3_column_int64(stmt.get(), 2);
                    first_row = false;
                }
                if (sqlite3_column_type(stmt.get(), 3) == SQLITE_NULL)
                    continue; // placeholder row -- the range subquery's columns with no
                              // matching event; process_live.id is an AUTOINCREMENT
                              // primary key and never legitimately 0
                const int64_t id = sqlite3_column_int64(stmt.get(), 3);
                ProcessEvent pe;
                pe.ts = sqlite3_column_int64(stmt.get(), 4);
                pe.action = std::string{col_text(stmt.get(), 5)};
                pe.pid = static_cast<uint32_t>(sqlite3_column_int64(stmt.get(), 6));
                pe.name = std::string{col_text(stmt.get(), 7)};
                pe.user = std::string{col_text(stmt.get(), 8)};
                events.push_back(std::move(pe));
                computed_new_hwm = std::max(computed_new_hwm, id);
            }
            if (rc != SQLITE_DONE) {
                h.fail("step gap-check/event query failed");
                return std::unexpected(std::string("step gap-check/event query failed"));
            }
            stmt.reset();

            int64_t effective_hwm = hwm;
            int64_t gap_lost = 0;
            if (row_count > 0 && hwm > 0 && min_id > hwm + 1) {
                gap_detected = true;
                gap_lost = min_id - hwm - 1;
                effective_hwm = min_id - 1;
                computed_new_hwm = std::max(computed_new_hwm, effective_hwm);
            }

            // ── Load the open-run table (usage_live) ──
            FoldState state;
            {
                sqlite3_stmt* open_raw = nullptr;
                if (sqlite3_prepare_v2(
                        h.raw(), "SELECT pid, exe_key, user, start_ts FROM usage_live WHERE "
                                 "action='open'",
                        -1, &open_raw, nullptr) != SQLITE_OK) {
                    h.fail("prepare usage_live read failed");
                    return std::unexpected(std::string("prepare usage_live read failed"));
                }
                LocalStmtPtr open_stmt(open_raw);
                int orc;
                while ((orc = sqlite3_step(open_stmt.get())) == SQLITE_ROW) {
                    OpenRun run;
                    run.pid = static_cast<uint32_t>(sqlite3_column_int64(open_stmt.get(), 0));
                    run.exe_key = std::string{col_text(open_stmt.get(), 1)};
                    run.user = std::string{col_text(open_stmt.get(), 2)};
                    run.start_ts = sqlite3_column_int64(open_stmt.get(), 3);
                    auto key = std::make_pair(run.pid, run.exe_key);
                    insert_open_run(state, key, std::move(run));
                }
                if (orc != SQLITE_DONE) {
                    h.fail("step usage_live read failed");
                    return std::unexpected(std::string("step usage_live read failed"));
                }
            }

            // ── Fold: pairing, expiry, cap ──
            std::vector<ClosedRun> closed;
            std::set<std::pair<uint32_t, std::string>> opened_this_tick;
            for (const auto& ev : events) {
                if (ev.action == "started")
                    opened_this_tick.insert({ev.pid, normalise_exe_key(ev.name)});
                if (auto c = apply_event(state, ev))
                    closed.push_back(std::move(*c));
            }
            // Guarded, proportionate to expire_open_runs' actual bounded harm
            // (open runs are capped at kMaxOpenRuns, so a wrong-clock jump
            // can wrongly close open runs at 0s duration, never delete
            // unbounded identity data -- the full clock-guarded-retention
            // seven-part machinery would be disproportionate here). Compare
            // `now` against the persisted anchor from the LAST fold tick: a
            // backward step, or a forward step wider than a generous number
            // of fast ticks could plausibly have elapsed, means `now` itself
            // is not trustworthy for an age comparison THIS tick -- decline
            // the expiry sweep only, not the whole fold (every other write
            // below still commits).
            constexpr int64_t kMaxPlausibleFoldGapSeconds = 86400; // 24h of missed ticks
            // `read_config_i64_strict`, not `read_config_i64_locked` -- the
            // latter's "0 on any fault" contract conflates a transient read
            // failure with a legitimate first-ever-fold absence; both must
            // decline THIS tick's sweep (TAR's own established convention,
            // quoted in .claude/routed-concerns.md's clock-guard row, treats
            // a missing stored reading as a decline trigger in its own
            // right).
            //
            // DELIBERATE (Wave 7 PR7.2b fix round 2, correcting fix round
            // 1's own overcorrection): the anchor ADVANCES to `now` on
            // EVERY tick below, including a declined one. Fix round 1 made
            // it advance only on a plausible tick, which reads as the safer
            // choice but is not: `usage_last_fold_ts` has exactly ONE writer
            // in this whole file (below), so once one tick declines, every
            // LATER tick compares `now` against that SAME frozen value --
            // the gap only grows, since real time never runs backward -- and
            // the sweep declines forever. An ordinary laptop closed over a
            // weekend (a routine >24h gap, not an attack) permanently and
            // silently disabled the 7-day open-run backstop for that device
            // under fix round 1's logic, with no recovery short of direct
            // `tar_config` surgery -- strictly worse than what it replaced.
            // There is no LOCAL, clock-reading-only way to tell "the clock
            // skipped once and is now stable-and-correct" (advancing is
            // right) from "the clock skipped once and is now
            // stable-but-still-wrong" (advancing is wrong) -- both produce
            // an identical next reading, so no cleverer local heuristic
            // closes this. Given that, and given the harm THIS guard bounds
            // is already capped (kMaxOpenRuns, 0s-duration closes credited
            // to `expired_runs`, never unbounded loss), unconditional
            // advance is the chosen tradeoff: self-healing after ordinary
            // sleep/wake within ~2 ticks is worth more than the narrow,
            // un-closeable protection against a sustained-broken-clock's
            // one-tick-delayed self-consistency. `usage_expiry_declined_count`
            // (written below alongside the other cumulative counters) makes
            // every decline countable on a fleet-status surface, so an
            // operator can see how often this fires without the guard
            // itself needing to become a one-way trap to be observable.
            const auto anchor = read_config_i64_strict(h, "usage_last_fold_ts");
            bool clock_plausible = false;
            bool anchor_declined = false;
            if (!anchor.has_value()) {
                spdlog::warn("TAR usage: declining this tick's open-run expiry sweep -- failed "
                            "to read the last-fold anchor ({}); re-anchoring to this tick's "
                            "clock",
                            anchor.error());
            } else if (!anchor->has_value()) {
                // Genuinely no anchor yet -- a freshly-baselined source has no
                // open runs to expire this early anyway, so declining costs
                // nothing.
            } else {
                const int64_t prior_fold_ts = **anchor;
                clock_plausible = now >= prior_fold_ts &&
                                  now - prior_fold_ts <= kMaxPlausibleFoldGapSeconds;
                if (!clock_plausible) {
                    anchor_declined = true;
                    spdlog::warn("TAR usage: declining this tick's open-run expiry sweep -- "
                                "`now` ({}) is implausible against the last fold's anchor ({}); "
                                "re-anchoring to this tick's clock so an ordinary sleep/wake "
                                "self-heals within ~2 ticks",
                                now, prior_fold_ts);
                }
            }
            if (clock_plausible) {
                for (auto& c : expire_open_runs(state, now))
                    closed.push_back(std::move(c));
            }
            for (auto& c : cap_open_runs(state))
                closed.push_back(std::move(c));

            events_seen = static_cast<int64_t>(events.size());
            runs_closed = static_cast<int64_t>(closed.size());
            // #4255: clamp non-negative -- max_id can trail computed_new_hwm
            // after the `process` feeder table is purged/reset mid-tick.
            lag_events = std::max<int64_t>(0, max_id - computed_new_hwm);
            new_hwm = computed_new_hwm;

            // ── Daily aggregate: ONE plain additive upsert per (day_ts, exe_key)
            // -- see file banner for why no replay guard is needed here ──
            for (const auto& d : fold_daily(closed)) {
                if (!h.exec(build_daily_upsert(d)))
                    return std::unexpected(h.error());
            }

            std::set<std::pair<int64_t, std::string>> touched_days;
            for (const auto& c : closed) {
                const int64_t day_ts = day_ts_for(c.start_ts);
                if (!h.exec(std::format("INSERT OR IGNORE INTO usage_daily_user (day_ts, "
                                        "exe_key, user) VALUES ({}, {}, {})",
                                        day_ts, sql_str(c.exe_key), sql_str(c.user))))
                    return std::unexpected(h.error());
                touched_days.insert({day_ts, c.exe_key});
            }
            for (const auto& [day_ts, exe_key] : touched_days) {
                if (!h.exec(std::format(
                        "UPDATE usage_daily SET distinct_users = (SELECT COUNT(DISTINCT user) "
                        "FROM usage_daily_user WHERE day_ts = {0} AND exe_key = {1}) WHERE "
                        "day_ts = {0} AND exe_key = {1}",
                        day_ts, sql_str(exe_key))))
                    return std::unexpected(h.error());
            }

            // usage_live: remove every key this tick touched at all, then
            // re-insert only the ones still open at the end.
            std::set<std::pair<uint32_t, std::string>> touched_keys = opened_this_tick;
            for (const auto& c : closed)
                touched_keys.insert({c.pid, c.exe_key});
            if (!touched_keys.empty()) {
                std::string in_list;
                for (const auto& [pid, exe_key] : touched_keys) {
                    if (!in_list.empty())
                        in_list += ",";
                    in_list += std::format("({},{})", pid, sql_str(exe_key));
                }
                if (!h.exec(std::format(
                        "DELETE FROM usage_live WHERE (pid, exe_key) IN (VALUES {})", in_list)))
                    return std::unexpected(h.error());
                for (const auto& key : touched_keys) {
                    auto it = state.open.find(key);
                    if (it == state.open.end())
                        continue; // touched but not open at the end -- delete only
                    const auto& run = it->second;
                    if (!h.exec(std::format(
                            "INSERT INTO usage_live (ts, snapshot_id, action, pid, exe_key, "
                            "user, start_ts) VALUES ({}, 0, 'open', {}, {}, {}, {})",
                            run.start_ts, run.pid, sql_str(run.exe_key), sql_str(run.user),
                            run.start_ts)))
                        return std::unexpected(h.error());
                }
            }

            // ── tar_config counters, in the SAME transaction ──
            auto upsert_config = [&](std::string_view key, std::string_view value) {
                return h.exec(std::format(
                    "INSERT INTO tar_config (key, value) VALUES ({}, {}) ON CONFLICT(key) DO "
                    "UPDATE SET value = excluded.value",
                    sql_str(key), sql_str(value)));
            };
            if (!upsert_config("usage_hwm_id", std::to_string(new_hwm)))
                return std::unexpected(h.error());
            if (!upsert_config("usage_lag_events", std::to_string(lag_events)))
                return std::unexpected(h.error());
            // Unconditional -- see the comment above the anchor read for why
            // a declined tick must still advance this.
            if (!upsert_config("usage_last_fold_ts", std::to_string(now)))
                return std::unexpected(h.error());
            if (anchor_declined) {
                const int64_t prior = read_config_i64_locked(h, "usage_expiry_declined_count");
                if (!upsert_config("usage_expiry_declined_count", std::to_string(prior + 1)))
                    return std::unexpected(h.error());
            }
            if (state.unmatched_stops > 0) {
                const int64_t prior = read_config_i64_locked(h, "usage_unmatched_stops");
                if (!upsert_config("usage_unmatched_stops",
                                   std::to_string(prior + state.unmatched_stops)))
                    return std::unexpected(h.error());
            }
            if (state.clock_anomalies > 0) {
                const int64_t prior = read_config_i64_locked(h, "usage_clock_anomalies");
                if (!upsert_config("usage_clock_anomalies",
                                   std::to_string(prior + state.clock_anomalies)))
                    return std::unexpected(h.error());
            }
            if (gap_detected) {
                const int64_t prior_count = read_config_i64_locked(h, "usage_gap_count");
                const int64_t prior_lost = read_config_i64_locked(h, "usage_gap_lost_events");
                if (!upsert_config("usage_gap_count", std::to_string(prior_count + 1)))
                    return std::unexpected(h.error());
                if (!upsert_config("usage_gap_lost_events", std::to_string(prior_lost + gap_lost)))
                    return std::unexpected(h.error());
                if (!upsert_config("usage_gap_last_ts", std::to_string(now)))
                    return std::unexpected(h.error());
            }
            return {};
        });

    if (!fold_result.has_value()) {
        result.ok = false;
        result.error = fold_result.error();
        // `hwm` may be 0 here if the strict read above is itself what failed
        // (no trustworthy value exists to report) -- no caller reads hwm_id
        // on the failure path (tar_plugin.cpp only checks `.ok`), so this is
        // diagnostic-only.
        result.hwm_id = hwm;
        return result;
    }

    result.ok = true;
    result.hwm_id = new_hwm;
    result.events_seen = events_seen;
    result.runs_closed = runs_closed;
    result.lag_events = lag_events;
    result.gap_detected = gap_detected;
    return result;
}

} // namespace yuzu::tar::usage
