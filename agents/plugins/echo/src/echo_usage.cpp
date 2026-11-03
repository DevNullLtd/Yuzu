/**
 * echo_usage.cpp -- the SQLite shell for the `usage` derived fold (see
 * echo_usage.hpp for the pure pairing logic and the lifecycle contract).
 *
 * usage_fold_in() is the ONE entry point that folds events. EchoDatabase::fold_process_events
 * passes it as the process fold's `extra`, so it runs INSIDE the transaction that upserts the
 * tick's process tiers; usage_sweep() is the same function on its own transaction with no
 * events, called once per fast tick so an open run still ages out on a tick with no process
 * event. usage_daily_user's own RETENTION prune is NOT here -- it runs under
 * echo_aggregator.cpp's clock-guarded run_retention instead, as its own independently-reachable
 * target (see docs/clock-guarded-retention.md).
 *
 * EVENT-FED, ONE TRANSACTION (v10). Before the roll-up flip the fold read raw process rows past
 * a persisted high-water mark and carried a gap check against the raw table's row-cap prune.
 * Raw rows are gone, so the events arrive in memory and the fold commits with the process tiers:
 * a failure of either rolls back both, and the caller re-offers the same events (the stream
 * path's pending_stream_evs_ retry, the snapshot path's re-diff), so a retried tick folds each
 * event into process AND usage exactly once. There is no hwm, no lag counter and no gap
 * machinery left to maintain; a crash can only land before the single COMMIT (SQLite's WAL
 * recovery rolls the whole thing back) or after it (everything durable together).
 *
 * CHECKED_TRANSACTION, NOT THE TOLERANT BATCH APIS (Wave 7 PR7.2b redo). Both round 1 and
 * round 2 of this source's adversarial review found the SAME invariant violated through
 * different code paths: a partial commit silently and permanently losing data (a tolerant batch
 * can commit with one statement skipped while a sibling write still advances). Every fix
 * patched the SPECIFIC reported scenario without hardening the shared primitive.
 * `EchoDatabase::checked_transaction` (echo_db.hpp) closes the invariant AT THE PRIMITIVE: it
 * commits ALL of a transaction's statements or NONE of them.
 *
 * READS ARE INSIDE THE TRANSACTION TOO. The lifecycle facts and the open-run table are read via
 * `TransactionHandle::raw()` in the same transaction as every write this pass produces --
 * `checked_transaction` holds the database mutex for its whole duration, so the READ that
 * decides this pass's deltas and the WRITE that commits them are one indivisible snapshot: a
 * concurrent `echo.purge_source usage` or an enable/disable edge cannot land in between. A
 * `raw()` caller must never call any OTHER `EchoDatabase` method that takes the mutex (it
 * would self-deadlock) -- see that method's own doc comment -- so every read below is
 * hand-rolled prepare/step against the raw connection, never `db.get_config()`.
 *
 * echo_config keys this file owns (P22/P24 read them, never write them):
 *   usage_unmatched_stops    -- cumulative, += per fold
 *   usage_clock_anomalies    -- cumulative, += per fold
 *   usage_last_fold_ts       -- epoch seconds of the last fold attempt (any outcome)
 *   usage_expiry_declined_count -- cumulative count of ticks whose open-run
 *                               expiry sweep declined for clock implausibility
 *   usage_feeder_enabled     -- "true"/"false", gating snapshot for P22's report
 *   usage_coverage_since     -- epoch seconds the active period has counted from
 *                               (informational -- lifecycle gating is by
 *                               generation, see usage_lifecycle_state, NOT this)
 *   usage_generation         -- bumped on every enable/disable edge (usage_set_enabled)
 *   usage_active_generation  -- the generation the last successful baseline stamped
 * The v10 migration deletes usage_hwm_id and usage_lag_events (no longer meaningful) and leaves
 * usage_gap_* as the historical counters they were: nothing increments them any more.
 */

#include "echo_usage.hpp"

#include "echo_aggregator.hpp" // source_enabled, canonical_source_enabled
#include "echo_schema_registry.hpp" // source_default_enabled

#include <sqlite3.h>
#include <spdlog/spdlog.h>

#include <charconv>
#include <format>
#include <memory>
#include <set>
#include <utility>

namespace yuzu::echo::usage {

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
// distinct from (and not shared with) echo_db.cpp's own file-local StmtPtr,
// which is not exposed through echo_db.hpp.
struct LocalStmtDeleter {
    void operator()(sqlite3_stmt* s) const { sqlite3_finalize(s); }
};
using LocalStmtPtr = std::unique_ptr<sqlite3_stmt, LocalStmtDeleter>;

std::string_view col_text(sqlite3_stmt* stmt, int idx) {
    const auto* txt = reinterpret_cast<const char*>(sqlite3_column_text(stmt, idx));
    return txt ? std::string_view{txt} : std::string_view{};
}

// The text of an echo_config row, read through the transaction's own connection (calling
// `db.get_config()` from inside a checked_transaction would try to reacquire `mu_` and deadlock):
// nullopt = no row (a real, legitimate state), an error = the read failed. Never poisons the
// handle -- each caller below owns that policy.
std::expected<std::optional<std::string>, std::string> read_config_raw(TransactionHandle& h,
                                                                       std::string_view key) {
    sqlite3_stmt* raw = nullptr;
    if (sqlite3_prepare_v2(h.raw(), "SELECT value FROM echo_config WHERE key = ?", -1, &raw,
                           nullptr) != SQLITE_OK)
        return std::unexpected(std::string("prepare failed"));
    LocalStmtPtr stmt(raw);
    sqlite3_bind_text(stmt.get(), 1, key.data(), static_cast<int>(key.size()), SQLITE_TRANSIENT);
    const int rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_DONE)
        return std::optional<std::string>{};
    if (rc != SQLITE_ROW)
        return std::unexpected(std::string("step failed"));
    return std::optional<std::string>(std::string{col_text(stmt.get(), 0)});
}

// Best-effort read of a cumulative status counter FROM INSIDE an open
// checked_transaction. A probe failure returns 0 rather
// than poisoning the handle: these four counters (unmatched_stops,
// clock_anomalies, gap_count, gap_lost_events) are cumulative,
// informational-only status -- not one of the fold's three core
// invariants -- so under-counting one tick's contribution on a transient
// read fault is the proportionate degrade, not failing the whole fold's
// data commit over a status counter.
int64_t read_config_i64_locked(TransactionHandle& h, std::string_view key) {
    const auto v = read_config_raw(h, key);
    return (v && *v) ? parse_i64(**v) : 0;
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
    const auto v = read_config_raw(h, key);
    if (!v)
        return std::unexpected(v.error());
    if (!*v)
        return std::optional<int64_t>{}; // genuinely absent -- no row, not a fault
    int64_t parsed = 0;
    const char* const end = (*v)->data() + (*v)->size();
    auto [p, ec] = std::from_chars((*v)->data(), end, parsed);
    if (ec != std::errc{} || p != end)
        return std::unexpected(std::string("malformed value"));
    return std::optional<int64_t>(parsed);
}

} // namespace

LifecycleState usage_lifecycle_state(EchoDatabase& db) {
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

bool usage_set_enabled(EchoDatabase& db, bool enabled, int64_t now) {
    const int64_t next_generation = parse_i64(db.get_config("usage_generation", "0")) + 1;
    auto result = db.checked_transaction(
        [&](TransactionHandle& h) -> std::expected<void, std::string> {
            if (!h.exec(std::format(
                    "INSERT INTO echo_config (key, value) VALUES ('usage_enabled', '{}') "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    enabled ? "true" : "false")))
                return std::unexpected(h.error());
            if (!h.exec(std::format(
                    "INSERT INTO echo_config (key, value) VALUES ('usage_paused_at', '{}') "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    enabled ? "0" : std::to_string(now))))
                return std::unexpected(h.error());
            // Bumped on EVERY edge, not only enable -- see echo_usage.hpp's file
            // banner. This is what forces usage_lifecycle_state to read
            // PendingBaseline the instant the source is next re-enabled, even
            // if nothing else ever explicitly invalidated the prior baseline.
            if (!h.exec(std::format(
                    "INSERT INTO echo_config (key, value) VALUES ('usage_generation', '{}') "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    next_generation)))
                return std::unexpected(h.error());
            return {};
        });
    if (!result.has_value()) {
        spdlog::error("Echo usage: {} transition failed to persist ({}); source remains at its "
                      "previous state",
                      enabled ? "enable" : "disable", result.error());
        return false;
    }
    return true;
}

namespace {

// A text config value through the transaction's own connection: nullopt = no row (a legitimate
// state), an error = the read failed (the handle is poisoned, so the caller's whole transaction
// rolls back rather than act on a guess).
std::expected<std::optional<std::string>, std::string> read_config_text(TransactionHandle& h,
                                                                        std::string_view key) {
    auto v = read_config_raw(h, key);
    if (!v) {
        h.fail("echo_config read failed: " + v.error());
        return std::unexpected(h.error());
    }
    return v;
}

// `<source>_enabled` through the handle: the canonical tri-state of #560, the registry default
// for a missing row. Only a confirmed "true" is on.
std::expected<bool, std::string> source_on(TransactionHandle& h, std::string_view source) {
    const auto v = read_config_text(h, std::format("{}_enabled", source));
    if (!v)
        return std::unexpected(v.error());
    return canonical_source_enabled(v->value_or(source_default_enabled(source) ? "true" : "false")) ==
           "true";
}

bool upsert_config(TransactionHandle& h, std::string_view key, std::string_view value) {
    return h.exec(std::format("INSERT INTO echo_config (key, value) VALUES ({}, {}) ON CONFLICT(key) "
                              "DO UPDATE SET value = excluded.value",
                              sql_str(key), sql_str(value)));
}

// Stamp a fresh baseline on the transaction's handle: forget the open runs, record the coverage
// start, and mark `generation` active. It stays on the handle (no db.set_config inside a
// checked_transaction), shared by usage_ensure_baselined and the PendingBaseline branch of
// usage_fold_in.
std::expected<void, std::string> stamp_baseline(TransactionHandle& h, int64_t now,
                                                int64_t generation) {
    if (!h.exec("DELETE FROM usage_live") ||
        !upsert_config(h, "usage_coverage_since", std::to_string(now)) ||
        !upsert_config(h, "usage_active_generation", std::to_string(generation)))
        return std::unexpected(h.error());
    return {};
}

} // namespace

std::expected<void, std::string> usage_ensure_baselined(EchoDatabase& db, int64_t now) {
    if (usage_lifecycle_state(db) != LifecycleState::PendingBaseline)
        return {}; // disabled, or already active under the current generation

    const int64_t generation = parse_i64(db.get_config("usage_generation", "0"));

    auto result = db.checked_transaction(
        [&](TransactionHandle& h) { return stamp_baseline(h, now, generation); });
    if (!result.has_value())
        spdlog::warn("Echo usage: baseline attempt failed ({}); will retry", result.error());
    return result;
}

std::expected<void, std::string> usage_fold_in(TransactionHandle& h, int64_t now,
                                               const std::vector<ProcessEvent>& events) {
    const auto usage_on = source_on(h, "usage");
    if (!usage_on)
        return std::unexpected(usage_on.error());
    const auto process_on = source_on(h, "process");
    if (!process_on)
        return std::unexpected(process_on.error());

    // Published on every pass (an unchanged value dirties no page): P22 reads it to know whether
    // an empty usage report means "nothing ran" or "nothing was collected".
    if (!h.exec(std::format(
            "INSERT INTO echo_config (key, value) VALUES ('usage_feeder_enabled', '{0}') "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value WHERE value IS NOT excluded.value",
            (*usage_on && *process_on) ? "true" : "false")))
        return std::unexpected(h.error());
    if (!*usage_on || !*process_on)
        return {}; // nothing to do this tick -- not a failure

    // ── Lifecycle, read through the handle: Active iff the two generations match. A missing or
    // unreadable active generation fails TOWARD re-baselining, never toward Active.
    const int64_t generation = read_config_i64_locked(h, "usage_generation");
    const auto active_text = read_config_text(h, "usage_active_generation");
    if (!active_text)
        return std::unexpected(active_text.error());
    const bool active = active_text->has_value() && parse_i64(**active_text) == generation;
    if (!active) {
        // PendingBaseline: stamp the baseline now. A freshly-established baseline has nothing yet
        // to fold forward from, so this tick's events fold into the process tiers only.
        return stamp_baseline(h, now, generation);
    }

    // ── Load the open-run table (usage_live) ──
    FoldState state;
    {
        sqlite3_stmt* open_raw = nullptr;
        if (sqlite3_prepare_v2(h.raw(),
                               "SELECT pid, exe_key, user, start_ts FROM usage_live WHERE "
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
    // Guarded, proportionate to expire_open_runs' actual bounded harm (open runs are capped at
    // kMaxOpenRuns, so a wrong-clock jump can wrongly close open runs at 0s duration, never
    // delete unbounded identity data -- the full clock-guarded-retention seven-part machinery
    // would be disproportionate here). Compare `now` against the persisted anchor from the LAST
    // fold tick: a backward step, or a forward step wider than a generous number of fast ticks
    // could plausibly have elapsed, means `now` itself is not trustworthy for an age comparison
    // THIS tick -- decline the expiry sweep only, not the whole fold (every other write below
    // still commits).
    constexpr int64_t kMaxPlausibleFoldGapSeconds = 86400; // 24h of missed ticks
    // `read_config_i64_strict`, not `read_config_i64_locked` -- the latter's "0 on any fault"
    // contract conflates a transient read failure with a legitimate first-ever-fold absence; both
    // must decline THIS tick's sweep (Echo's own established convention, quoted in
    // .claude/routed-concerns.md's clock-guard row, treats a missing stored reading as a decline
    // trigger in its own right).
    //
    // DELIBERATE (Wave 7 PR7.2b fix round 2): the anchor ADVANCES to `now` on EVERY tick below,
    // including a declined one. `usage_last_fold_ts` has exactly ONE writer in this file, so once
    // one tick declines, every LATER tick would compare `now` against that SAME frozen value --
    // the gap only grows -- and the sweep would decline forever. An ordinary laptop closed over a
    // weekend (a routine >24h gap, not an attack) would permanently disable the 7-day open-run
    // backstop. There is no LOCAL, clock-reading-only way to tell "the clock skipped once and is
    // now correct" from "the clock skipped once and is still wrong", and the harm this guard
    // bounds is already capped (kMaxOpenRuns, 0s-duration closes credited to `expired_runs`), so
    // unconditional advance is the chosen tradeoff. `usage_expiry_declined_count` makes every
    // decline countable on a fleet-status surface.
    const auto anchor = read_config_i64_strict(h, "usage_last_fold_ts");
    bool clock_plausible = false;
    bool anchor_declined = false;
    if (!anchor.has_value()) {
        spdlog::warn("Echo usage: declining this tick's open-run expiry sweep -- failed to read the "
                     "last-fold anchor ({}); re-anchoring to this tick's clock",
                     anchor.error());
    } else if (!anchor->has_value()) {
        // Genuinely no anchor yet -- a freshly-baselined source has no open runs to expire this
        // early anyway, so declining costs nothing.
    } else {
        const int64_t prior_fold_ts = **anchor;
        clock_plausible =
            now >= prior_fold_ts && now - prior_fold_ts <= kMaxPlausibleFoldGapSeconds;
        if (!clock_plausible) {
            anchor_declined = true;
            spdlog::warn("Echo usage: declining this tick's open-run expiry sweep -- `now` ({}) is "
                         "implausible against the last fold's anchor ({}); re-anchoring to this "
                         "tick's clock so an ordinary sleep/wake self-heals within ~2 ticks",
                         now, prior_fold_ts);
        }
    }
    if (clock_plausible) {
        for (auto& c : expire_open_runs(state, now))
            closed.push_back(std::move(c));
    }
    for (auto& c : cap_open_runs(state))
        closed.push_back(std::move(c));

    // ── Daily aggregate: ONE plain additive upsert per (day_ts, exe_key) -- no replay guard is
    // needed: the whole fold is inside the caller's transaction, so a retried tick finds nothing
    // of a failed predecessor ──
    for (const auto& d : fold_daily(closed)) {
        if (!h.exec(build_daily_upsert(d)))
            return std::unexpected(h.error());
    }

    std::set<std::pair<int64_t, std::string>> touched_days;
    for (const auto& c : closed) {
        const int64_t day_ts = day_ts_for(c.start_ts);
        if (!h.exec(std::format("INSERT OR IGNORE INTO usage_daily_user (day_ts, exe_key, user) "
                                "VALUES ({}, {}, {})",
                                day_ts, sql_str(c.exe_key), sql_str(c.user))))
            return std::unexpected(h.error());
        touched_days.insert({day_ts, c.exe_key});
    }
    for (const auto& [day_ts, exe_key] : touched_days) {
        if (!h.exec(std::format(
                "UPDATE usage_daily SET distinct_users = (SELECT COUNT(DISTINCT user) FROM "
                "usage_daily_user WHERE day_ts = {0} AND exe_key = {1}) WHERE day_ts = {0} AND "
                "exe_key = {1}",
                day_ts, sql_str(exe_key))))
            return std::unexpected(h.error());
    }

    // usage_live: remove every key this tick touched at all, then re-insert only the ones still
    // open at the end.
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
        if (!h.exec(std::format("DELETE FROM usage_live WHERE (pid, exe_key) IN (VALUES {})", in_list)))
            return std::unexpected(h.error());
        for (const auto& key : touched_keys) {
            auto it = state.open.find(key);
            if (it == state.open.end())
                continue; // touched but not open at the end -- delete only
            const auto& run = it->second;
            if (!h.exec(std::format(
                    "INSERT INTO usage_live (ts, snapshot_id, action, pid, exe_key, user, start_ts) "
                    "VALUES ({}, 0, 'open', {}, {}, {}, {})",
                    run.start_ts, run.pid, sql_str(run.exe_key), sql_str(run.user), run.start_ts)))
                return std::unexpected(h.error());
        }
    }

    // ── echo_config counters, in the SAME transaction ──
    // Unconditional -- see the comment above the anchor read for why a declined tick must still
    // advance this.
    if (!upsert_config(h, "usage_last_fold_ts", std::to_string(now)))
        return std::unexpected(h.error());
    if (anchor_declined) {
        const int64_t prior = read_config_i64_locked(h, "usage_expiry_declined_count");
        if (!upsert_config(h, "usage_expiry_declined_count", std::to_string(prior + 1)))
            return std::unexpected(h.error());
    }
    if (state.unmatched_stops > 0) {
        const int64_t prior = read_config_i64_locked(h, "usage_unmatched_stops");
        if (!upsert_config(h, "usage_unmatched_stops", std::to_string(prior + state.unmatched_stops)))
            return std::unexpected(h.error());
    }
    if (state.clock_anomalies > 0) {
        const int64_t prior = read_config_i64_locked(h, "usage_clock_anomalies");
        if (!upsert_config(h, "usage_clock_anomalies", std::to_string(prior + state.clock_anomalies)))
            return std::unexpected(h.error());
    }
    return {};
}

std::expected<void, std::string> usage_sweep(EchoDatabase& db, int64_t now) {
    return db.checked_transaction(
        [&](TransactionHandle& h) { return usage_fold_in(h, now, {}); });
}

} // namespace yuzu::echo::usage
