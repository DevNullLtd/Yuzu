/**
 * file_search_driver.hpp -- ONE slice of the on-demand file search as a pure state machine over injected
 * boundaries (file_search_legs.hpp). The agent is stateless between calls but for the in-memory
 * SearchState; the caller holds the cursor and loops.
 *
 * THE FLOW of run_slice, in order (each step is a return point; every one releases the slot):
 *   1. decode the cursor (strictly, and its mac under the process's key: a cursor this agent process did
 *      not issue, a forged one or one from before an agent restart, answers `invalid`/bad_cursor before any
 *      boundary is called) and refuse invalid GovernorLimits before a governor is built;
 *   2. take the single-flight slot (a second call answers `busy` at once, touching nothing);
 *   3. drop abandoned workers that have returned; two still running answer `busy`;
 *   4. read the mount table (unreadable or malformed answers `failed`, mount_table_unreadable), plan the
 *      volumes and check the cursor against the plan (a changed unit set ends the search with
 *      mount_table_changed);
 *   5. the current volume is stalled (an abandoned worker is still blocked in it): emit it as stalled,
 *      count one gap and move on to the next volume without walking;
 *   6. otherwise run the unit's slice on a worker through the bounded runner (slice time + grace). The
 *      worker makes the unit's leg (the leg factory runs INSIDE the bound, never before it), on the first
 *      slice asks the leg what the root is (a link, a missing path, a file: `invalid` with that token, no
 *      walk), reads the unit's user roots once (only for a root that was not refused), then runs
 *      walk_ordered with the match visitor. So no leg code and no profile read runs before the cursor is
 *      authenticated, the slot is taken and the worker is running;
 *   7. on the pool thread: record the slice, build the next cursor (only after the transition validator
 *      accepts it), the rows and the verdict.
 *
 * ONE VOLUME PER SLICE. A slice never mixes volumes: every state write and every row is made by the pool
 * thread, and a stalled volume cannot hold up the rest.
 *
 * THREADS. The worker touches only values and shared pointers it owns (WorkInput: copies of the leg
 * factory, the unit and the user-roots reader) and the OS through its leg; it never reads the slot, the
 * SearchState or the caller's Boundaries. It sets its own done flag when it
 * returns, even by exception, and that flag is the only way an abandoned worker is ever seen to finish.
 * The slot is released ONLY by the pool thread of the slice that took it, through one RAII guard.
 *
 * ROWS. Matches and their extents rows first, then the coverage block (volume, gap, gaps_dropped,
 * volumes_dropped, coverage rows), the cursor row when one is issued, and last the one `search` trailer. An
 * invalid or busy answer is the trailer alone. An empty answer is therefore never confusable with a failed
 * or partial one: the trailer says which, and the coverage row says whether it is complete.
 *
 * THE VERDICT lives in the coverage row, cumulative across slices through the cursor's prior_gaps, and
 * reads partial for anything not searched: a refused mount (counted once, on the first slice, and again only
 * if the refused set changes), a stalled volume, a gap, a dropped volume, an unfinished search.
 */
#pragma once

#include <file_search_coverage.hpp>
#include <file_search_governor.hpp>
#include <row_byte_budget.hpp>

#include "component_walk.hpp"
#include "file_search_extents.hpp"
#include "file_search_legs.hpp"
#include "file_search_request.hpp"
#include "file_search_rows.hpp"
#include "file_search_state.hpp"
#include "file_search_volumes.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <limits>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yuzu::file_search {

// ---- the one mapping of the governor's limits to the walk's ----

/// The walk limits of a slice: entries and rows from the governor, depth as deep as a position can name,
/// the per-directory listing cap left at its default. The ONE place the two are mapped.
[[nodiscard]] inline ci::WalkLimits walk_limits_for(const fsr::GovernorLimits& g) {
    ci::WalkLimits w;
    w.max_entries = g.max_entries;
    w.max_rows = g.max_rows;
    w.max_wall = std::chrono::duration_cast<std::chrono::seconds>(g.slice);
    w.max_depth = fsr::kMaxPositionDepth;
    return w;
}

/// The ONE seeding of a slice's coverage envelope: the running gap count and the slice number from the
/// cursor, the planned-but-dropped volumes from the plan. Nothing else is carried between slices.
[[nodiscard]] inline fsr::CoverageEnvelope seed_envelope(const fsr::Cursor& c, const VolumePlan& plan) {
    fsr::CoverageEnvelope e;
    e.prior_gaps = c.prior_gaps;
    e.slices = c.sequence >= (std::numeric_limits<std::uint32_t>::max)() ? (std::numeric_limits<std::uint32_t>::max)()
                                                                          : static_cast<std::uint32_t>(c.sequence + 1);
    e.volumes_dropped = plan.volumes_dropped;
    return e;
}

// ---- what the worker returns, what the driver is given ----

/// What a worker hands back. It is a value: a worker that times out leaves its copy to nobody.
struct WorkResult {
    bool threw{false};
    std::optional<RequestError> root_error; // the first slice's root check refused the root
    ci::OrderedResult walk;
    std::vector<std::string> rows; // match and extents rows, in walk order
    std::vector<fsr::Gap> gaps;    // gaps the visitor found: an unevaluable name, a match cap
    std::size_t gaps_dropped{0};
    bool cancelled{false};         // the stop flag ended the walk
};

/// Everything the driver needs, as references that live as long as the call.
struct Boundaries {
    SearchState& state;
    std::atomic<bool>& slot; // the process-wide single-flight slot
    MountReader read_mounts{};
    LegFactory make_leg{};
    /// The profile directories of a unit's volume that the built-in user-directory rule does not reach, as
    /// labels in the unit's namespace. Called on the slice's worker; unset reads none.
    std::function<std::vector<std::string>(const Unit&)> read_user_roots{};
    BoundedRunner<WorkResult> run_bounded{};
    std::function<fsr::Clock::time_point()> now{};
    std::function<void(std::chrono::milliseconds)> sleep{};
    std::function<bool()> stop_requested{}; // optional: polled between entries; true ends the walk
    fsr::GovernorLimits limits{};         // the defaults are the ruled slice, entry and row budgets
    Os os{Os::linux_os};
    CursorKey cursor_key{};               // the process's cursor key; all zero (never set) is refused
};

/// Counters of one slice, for the heartbeat tags and the log: each is 0 or 1 except `gaps`.
struct SliceCounters {
    unsigned slices{0};
    unsigned budget_stops{0};
    unsigned stalled{0};
    unsigned unstable{0};
    unsigned timed_out{0};
    unsigned rejected{0};
    unsigned failed{0};
    std::size_t gaps{0};
};

struct SliceResult {
    Status status{Status::failed};
    std::string reason{"none"};
    std::vector<std::string> rows; // the last row is the search trailer
    std::string cursor;            // the next cursor's token; empty when the search is over or retried
    std::string query;             // query_prefix(): names the search in a log line
    SliceCounters counters;
};

namespace driver_detail {

/// Everything the worker owns. Copies only: no reference to the caller's state.
struct WorkInput {
    LegFactory make_leg; // called on the worker, inside the bound
    Unit unit;
    std::function<std::vector<std::string>(const Unit&)> read_user_roots; // likewise; may be empty
    fsr::Pattern pattern;
    fsr::Kinds kinds{fsr::Kinds::files};
    std::string search_root;
    std::string walk_root;
    fsr::Position resume;
    ci::WalkLimits walk;
    fsr::GovernorLimits limits;
    std::function<fsr::Clock::time_point()> now;
    std::function<void(std::chrono::milliseconds)> sleep;
    std::function<bool()> stop;
    bool check_root{false};
    Os os{Os::linux_os};
    DoneFlag done;
};

struct DoneOnExit {
    DoneFlag flag;
    ~DoneOnExit() {
        if (flag)
            flag->store(true, std::memory_order_release);
    }
};

struct DirTally {
    std::size_t matches{0};
    bool capped{false};
};

/// The ONE gap rule, for the worker's own list and the pool thread's envelope alike: a gap whose path fits
/// is kept up to fsr::kMaxGaps; any other is counted in `dropped`, never emitted.
inline void add_bounded_gap(std::vector<fsr::Gap>& gaps, std::size_t& dropped, std::string path,
                            fsr::GapCause cause) {
    if (!gap_path_fits(path) || gaps.size() >= fsr::kMaxGaps)
        ++dropped;
    else
        gaps.push_back({std::move(path), cause});
}

/// The worker body. Never throws: a throw is reported as `threw`, never mistaken for a timeout.
[[nodiscard]] inline WorkResult run_unit(WorkInput in) {
    using Type = ci::DirEntry::Type;
    WorkResult out;
    const DoneOnExit done{in.done};
    try {
        const UnitLeg leg = in.make_leg(in.unit);
        if (in.check_root) {
            switch (leg.root_state(in.search_root)) {
            case ci::RootState::is_link:
                out.root_error = RequestError::root_is_link;
                return out;
            case ci::RootState::not_found:
                out.root_error = RequestError::root_not_found;
                return out;
            case ci::RootState::not_a_directory:
                out.root_error = RequestError::root_not_a_directory;
                return out;
            case ci::RootState::ok:
            case ci::RootState::other: // the walk's own root gap says the rest
                break;
            }
        }
        // Read once per slice, and only for a root that was not refused (the boundary stays a worker read).
        const std::vector<std::string> user_roots =
            in.read_user_roots ? in.read_user_roots(in.unit) : std::vector<std::string>{};

        fsr::SliceGovernor gov(in.limits, {in.now, in.sleep});
        ci::FsOps ops = leg.ops;
        ops.now = in.now; // one clock for the governor's deadline and the walk's reads of it
        // A resumed slice re-lists every ancestor of its resume point before it visits an entry, and
        // those listings reach nothing new: they are paced like any work but not judged by the back-off,
        // or a slow disk would spend the slice on the way back to where the last one stopped. `judge`
        // starts true only for a slice with no resume position at all (a cursor that stopped in the root
        // has `after` set and no `dirs`) and turns true when the walk visits its first entry.
        bool judge = in.resume.dirs.empty() && in.resume.after.empty();
        ops.list = [&gov, &judge, now = in.now, list = leg.ops.list](const std::string& dir, std::size_t cap) {
            gov.pace();
            const auto before = now();
            auto listed = list(dir, cap);
            const auto took = now() - before;
            if (judge)
                gov.note_listing(took); // the governor's back-off baseline: the search's own new listings
            return listed;
        };

        yuzu::shared::RowByteBudget budget{.max_bytes = kMatchRowBudget}; // the match and extents rows of this slice
        std::unordered_map<std::string, DirTally> per_dir;
        const auto add_gap = [&out](std::string path, fsr::GapCause cause) {
            add_bounded_gap(out.gaps, out.gaps_dropped, std::move(path), cause);
        };

        const ci::OrderedVisit visit = [&](const std::string& dir, const ci::DirEntry& e, std::uint64_t dir_dev) {
            gov.pace();
            judge = true;
            const bool is_dir = e.type == Type::dir;
            if (is_dir ? in.kinds == fsr::Kinds::files : in.kinds == fsr::Kinds::directories)
                return false;
            const std::string full = ci::walk_detail::join(dir, e.name);
            switch (in.pattern.evaluate(e.name)) {
            case fsr::Match::no:
                return false;
            case fsr::Match::not_evaluated: // too long to compare: not searched, and says so
                add_gap(full, fsr::GapCause::name_too_long);
                return false;
            case fsr::Match::yes:
                break;
            }
            DirTally& tally = per_dir[dir];
            if (tally.matches >= kMaxMatchesPerDirectory) {
                if (!tally.capped) {
                    tally.capped = true;
                    add_gap(dir, fsr::GapCause::match_cap);
                }
                return false;
            }
            ++tally.matches;

            MatchInfo m;
            m.path = full;
            m.kind = is_dir ? fsr::EntryKind::directory : fsr::EntryKind::file;
            m.id = {dir_dev, e.file_id};
            m.scope = is_user_profile_path(full, in.os) || under_user_root(full, user_roots, in.os) ? Scope::user
                                                                                                    : Scope::system;
            std::string extents_row;
            if (!is_dir) { // a file is opened for its facts and never read; a directory is never opened
                const FileFacts f = leg.facts(dir, e); // the leg owns its extents state, never rewritten here
                if (f.facts.opened) {
                    m.size = f.facts.size;
                    m.mtime = f.facts.mtime;
                }
                extents_row = format_extents_row(m.id, f.extents);
            }
            std::string row = format_match_row(m);
            if (row.size() > kMaxMatchRowBytes || extents_row.size() > kMaxMatchRowBytes) {
                add_gap(full, fsr::GapCause::name_too_long); // cannot be reported within the row bound
                return false;
            }
            budget.add(row.size() + 1 + (extents_row.empty() ? 0 : extents_row.size() + 1),
                       extents_row.empty() ? 1 : 2);
            out.rows.push_back(std::move(row));
            if (!extents_row.empty())
                out.rows.push_back(std::move(extents_row));
            return true;
        };
        // Full once one more match with its extents might not fit the budget: the walker's second row cap,
        // so the slice ends BEFORE a row would overflow and never drops one.
        const std::function<bool()> rows_full = [&] {
            return !budget.fits(2 * kMaxMatchRowBytes, 0) || (in.stop && in.stop());
        };

        out.walk = ci::walk_ordered(in.walk_root, in.resume, in.walk, ops, gov.deadline(), visit,
                                    ci::kMaxOrderedRetainedBytes, rows_full);
        out.cancelled = in.stop && in.stop();
    } catch (...) {
        out = WorkResult{};
        out.threw = true;
    }
    return out;
}

[[nodiscard]] inline fsr::VolumeCoverage refused_row(const Refused& r) {
    fsr::VolumeCoverage v;
    v.mount_point = r.mount_point;
    v.fstype = r.fstype;
    // A macOS data volume under "/" is searched through the firmlinks of the system volume, so its row says
    // partial; every other refused mount is never searched.
    v.state = r.reason == fsr::Reason::firmlinks_only ? fsr::VolumeState::partial : fsr::VolumeState::not_searched;
    v.reason = r.reason;
    return v;
}

} // namespace driver_detail

/// Runs one slice of the search `req` over `b`. Never throws and never blocks past the slice time plus
/// grace: a worker that does not return is abandoned and recorded.
[[nodiscard]] inline SliceResult run_slice(const Request& req, Boundaries& b) {
    using driver_detail::WorkInput;
    SliceResult out;
    const fsr::QueryHash qh = fsr::query_hash(req.query);
    Trailer trailer;
    trailer.semantics = req.query.pattern.semantics_id();
    trailer.query = query_prefix(qh);
    out.query = trailer.query;

    // The trailer alone: nothing ran, so there is no coverage to state.
    const auto bare = [&](Status status, std::string reason) {
        trailer.status = status;
        trailer.reason = std::move(reason);
        out.status = status;
        out.reason = trailer.reason;
        out.rows = {format_search_row(trailer)};
        return out;
    };

    // 1. the key, the cursor strictly under it, then the limits
    if (std::ranges::all_of(b.cursor_key, [](unsigned char byte) { return byte == 0; }))
        return bare(Status::failed, to_token(Fault::internal_error)); // a key nobody set would sign any token
    std::optional<VolumeCursor> outer;
    if (!req.cursor.empty()) {
        outer = decode_volume_cursor(req.cursor, qh, b.cursor_key);
        if (!outer || outer->inner.sequence >= kMaxSlices)
            return bare(Status::invalid, to_token(RequestError::bad_cursor));
    }
    if (!fsr::valid(b.limits))
        return bare(Status::failed, to_token(Fault::internal_error));
    const fsr::Cursor inner = outer ? outer->inner : fsr::Cursor{qh};
    trailer.sequence = inner.sequence;

    // 2. the slot: taken first, released by this call on every path
    bool expected = false;
    if (!b.slot.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return bare(Status::busy, to_token(Fault::busy));
    struct SlotGuard {
        std::atomic<bool>& slot;
        ~SlotGuard() { slot.store(false, std::memory_order_release); }
    } const slot_guard{b.slot};

    // 3. workers that have returned are forgotten; two still blocked mean no room for a third
    b.state.drop_finished();
    if (b.state.abandoned_full())
        return bare(Status::busy, to_token(Fault::busy));

    // The rows of a slice that ran: matches, the coverage block, the cursor, the trailer.
    SliceCounters counters;
    counters.slices = 1;
    const auto conclude = [&](const fsr::CoverageEnvelope& env, std::vector<std::string> match_rows, Status status,
                              std::string reason, std::string cursor, std::size_t links_skipped) {
        out.rows = std::move(match_rows);
        for (auto& row : fsr::format_coverage_rows(env))
            out.rows.push_back(std::move(row));
        if (!cursor.empty())
            out.rows.push_back(format_cursor_row(cursor));
        trailer.status = status;
        trailer.reason = reason;
        trailer.links_skipped = links_skipped;
        out.rows.push_back(format_search_row(trailer));
        out.status = status;
        out.reason = std::move(reason);
        out.cursor = std::move(cursor);
        if (status == Status::failed)
            counters.failed = 1;
        counters.gaps = env.gaps.size() + env.gaps_dropped;
        out.counters = counters;
        return out;
    };

    // 4. the mount table, the plan, the cursor against the plan
    const auto table = b.read_mounts ? b.read_mounts(req.query.root) : std::nullopt;
    if (!table || table->malformed > 0)
        return conclude(seed_envelope(inner, VolumePlan{}), {}, Status::failed,
                        fsr::to_token(fsr::Reason::mount_table_unreadable), {}, 0);
    const VolumePlan plan = build_plan(*table, req.query.root, b.os);
    if (!plan.valid)
        return conclude(seed_envelope(inner, plan), {}, Status::failed,
                        fsr::to_token(fsr::Reason::mount_table_unreadable), {}, 0);
    if (outer && outer->units_hash != plan.units_hash)
        return conclude(seed_envelope(inner, plan), {}, Status::failed,
                        fsr::to_token(fsr::Reason::mount_table_changed), {}, 0);
    if (outer && outer->index >= plan.units.size())
        return bare(Status::invalid, to_token(RequestError::bad_cursor));

    const std::size_t index = outer ? outer->index : 0;
    const bool emit_refused = !outer || outer->refused_hash != plan.refused_hash;
    const std::size_t refused_counted = emit_refused ? plan.refused.size() : 0;

    fsr::CoverageEnvelope env = seed_envelope(inner, plan);
    const auto add_refused_rows = [&] {
        if (emit_refused)
            for (const auto& r : plan.refused)
                env.volumes.push_back(driver_detail::refused_row(r));
    };

    // Nothing to walk: every mount in scope was refused (or none could be planned). Never complete.
    if (plan.units.empty()) {
        add_refused_rows();
        return conclude(env, {}, Status::ok, fsr::to_token(fsr::Reason::none), {}, 0);
    }
    const Unit& unit = plan.units[index];
    const bool last_unit = index + 1 >= plan.units.size();
    const Lineage lineage{qh, inner.sequence, inner.generation};

    fsr::VolumeCoverage vol;
    vol.mount_point = unit.mount_point;
    vol.fstype = unit.fstype;
    vol.extents = fsr::Extents::collected;
    // The unit's own row, then the refused rows: the one place both are emitted, so no path forgets them.
    const auto emit_vol = [&] {
        env.volumes.push_back(vol);
        add_refused_rows();
    };

    // The cursor that follows this slice: the token, or no value when the search finished (a finished search
    // has no cursor), or the reason it ends here. `rest` is set by an end that is final for the search (here
    // max_slices; stalled and unstable below): the reason the units after this one are named with. A
    // retryable end, cancelled, mount_table_changed and cursor_refused leave it empty. `gap_delta` is what
    // the running count grows by.
    struct CursorEnd {
        std::string why;
        std::optional<fsr::Reason> rest = std::nullopt;
    };
    using NextCursor = std::expected<std::optional<std::string>, CursorEnd>;
    const auto next_cursor_for = [&](bool unit_done, const fsr::Position& position, bool restarted,
                                     std::size_t gap_delta) -> NextCursor {
        if (unit_done && last_unit)
            return std::nullopt;
        const fsr::Cursor next_inner = fsr::next_cursor(inner, unit_done ? fsr::Position{} : position,
                                                        unit_done ? false : restarted, gap_delta);
        if (next_inner.sequence >= kMaxSlices)
            return std::unexpected(CursorEnd{fsr::to_token(fsr::Reason::max_slices), fsr::Reason::max_slices});
        const VolumeCursor next{unit_done ? index + 1 : index, plan.units_hash, plan.refused_hash, next_inner};
        const VolumeCursor prev{index, plan.units_hash, plan.refused_hash, inner};
        if (!volume_advances(prev, next))
            return std::unexpected(CursorEnd{to_token(Fault::cursor_refused)});
        std::string token = encode_volume_cursor(next, b.cursor_key);
        if (token.empty()) // a non-complete stop must never read as "finished"
            return std::unexpected(CursorEnd{to_token(Fault::internal_error)});
        return token;
    };
    // The units after this one when the search ends for good before reaching them (max_slices, stalled,
    // unstable): said, never silent, each with the reason on the `search` row. An end whose previous cursor
    // stands, a cancel, a changed mount table and a refused cursor do not call it.
    const auto not_searched_rest = [&](std::size_t from, fsr::Reason why) {
        for (std::size_t i = from; i < plan.units.size(); ++i) {
            fsr::VolumeCoverage v;
            v.mount_point = plan.units[i].mount_point;
            v.fstype = plan.units[i].fstype;
            v.state = fsr::VolumeState::not_searched;
            v.reason = why;
            env.volumes.push_back(std::move(v));
        }
    };

    // 5. the current volume is stalled: say so, count one gap, move on without walking
    if (b.state.is_stalled(unit.key())) {
        vol.state = fsr::VolumeState::partial;
        vol.reason = fsr::Reason::stalled;
        emit_vol();
        counters.stalled = 1;
        const NextCursor next = next_cursor_for(true, {}, false, 1 + refused_counted);
        if (!next) {
            if (next.error().rest)
                not_searched_rest(index + 1, *next.error().rest);
            return conclude(env, {}, Status::failed, next.error().why, {}, 0);
        }
        env.has_cursor = next->has_value();
        return conclude(env, {}, Status::ok, fsr::to_token(fsr::Reason::stalled), next->value_or(std::string{}), 0);
    }

    // 6. the unit's slice on a worker, bounded
    const DoneFlag done = make_done_flag();
    WorkInput work{.make_leg = b.make_leg,
                   .unit = unit,
                   .read_user_roots = b.read_user_roots,
                   .pattern = req.query.pattern,
                   .kinds = req.query.kinds,
                   .search_root = req.query.root,
                   .walk_root = unit.walk_root,
                   .resume = inner.position,
                   .walk = walk_limits_for(b.limits),
                   .limits = b.limits,
                   .now = b.now,
                   .sleep = b.sleep,
                   .stop = b.stop_requested,
                   .check_root = !outer,
                   .os = b.os,
                   .done = done};
    RunOutcome<WorkResult> ran =
        b.run_bounded(b.limits.slice + kSliceGrace, [work = std::move(work)]() { return driver_detail::run_unit(work); });

    // A slice that returned no result (refused a worker, timed out, threw) is a non-advancing attempt on
    // its cursor, counted per lineage: the third in a row ends the search stalled. Its volume row reads
    // partial/stalled in all three cases: that is the one token for "no result", and the attempt did not
    // advance. Only a timed-out slice leaves a worker blocked, and only that one is added to the abandoned
    // list (below), which is what makes later slices skip the volume.
    const auto no_result = [&](Fault fault) {
        const fsr::GovernorState gov =
            fsr::record_failed_slice(b.state.carried(lineage), b.limits, inner.generation);
        b.state.store(lineage, gov);
        vol.state = fsr::VolumeState::partial;
        vol.reason = fsr::Reason::stalled;
        emit_vol();
        std::string reason = to_token(fault);
        if (gov.health != fsr::Health::ok) { // not retryable: the search ends here, so name what it never reached
            const bool stalled = gov.health == fsr::Health::stalled;
            const fsr::Reason why = stalled ? fsr::Reason::stalled : fsr::Reason::unstable;
            (stalled ? counters.stalled : counters.unstable) = 1;
            reason = fsr::to_token(why);
            not_searched_rest(index + 1, why);
        }
        return conclude(env, {}, Status::failed, reason, {}, 0);
    };
    if (ran.status == RunStatus::rejected) {
        counters.rejected = 1;
        return no_result(Fault::rejected);
    }
    if (ran.status == RunStatus::timed_out) {
        counters.timed_out = 1;
        b.state.add_abandoned(unit.key(), done); // never blocks: the list had room when the slice began
        return no_result(Fault::timed_out);
    }
    if (!ran.value || ran.value->threw)
        return no_result(Fault::internal_error);
    WorkResult& w = *ran.value;

    if (w.root_error)
        return bare(Status::invalid, to_token(*w.root_error));

    // 7. the slice's result
    ci::OrderedResult& res = w.walk;
    for (auto& g : res.gaps)
        driver_detail::add_bounded_gap(env.gaps, env.gaps_dropped, std::move(g.path), g.cause);
    for (auto& g : w.gaps)
        driver_detail::add_bounded_gap(env.gaps, env.gaps_dropped, std::move(g.path), g.cause);
    env.gaps_dropped += res.gaps_dropped + w.gaps_dropped;
    vol.entries = res.stats.entries;
    const bool complete = res.stop == ci::Stop::complete;
    const std::size_t gap_delta = env.gaps.size() + env.gaps_dropped + refused_counted;

    if (w.cancelled) { // the agent is shutting down: nothing is carried, nothing is retried
        vol.state = fsr::VolumeState::partial;
        vol.reason = fsr::Reason::cancelled;
        emit_vol();
        return conclude(env, std::move(w.rows), Status::failed, fsr::to_token(fsr::Reason::cancelled), {},
                        res.stats.links_skipped);
    }

    fsr::GovernorState gov = fsr::record_slice(b.state.carried(lineage), b.limits, res.advanced, res.restarted,
                                               inner.generation);
    b.state.store(lineage, gov);
    if (!complete)
        counters.budget_stops = 1;

    if (complete) {
        vol.state = fsr::VolumeState::complete;
        vol.reason = fsr::Reason::none;
    } else {
        vol.state = fsr::VolumeState::partial;
        vol.reason = reason_for(res.stop, gov.health);
    }

    NextCursor next = std::unexpected(CursorEnd{to_token(Fault::internal_error)});
    if (!complete && gov.health != fsr::Health::ok) { // stalled or unstable: final
        counters.stalled = gov.health == fsr::Health::stalled ? 1 : 0;
        counters.unstable = gov.health == fsr::Health::unstable ? 1 : 0;
        next = std::unexpected(CursorEnd{fsr::to_token(vol.reason), vol.reason}); // stalled or unstable
    } else if (!complete && !res.advanced && !res.restarted) { // no progress: retry this cursor
        next = std::unexpected(CursorEnd{to_token(Fault::no_progress)});
    } else {
        next = next_cursor_for(complete, res.position, res.restarted, gap_delta);
        if (!next && next.error().rest && !complete)
            vol.reason = *next.error().rest; // this unit was cut by the slice maximum
    }

    emit_vol();
    if (!next) {
        if (next.error().rest)
            not_searched_rest(index + 1, *next.error().rest);
        return conclude(env, std::move(w.rows), Status::failed, next.error().why, {}, res.stats.links_skipped);
    }
    env.has_cursor = next->has_value();
    return conclude(env, std::move(w.rows), Status::ok, fsr::to_token(vol.reason), next->value_or(std::string{}),
                    res.stats.links_skipped);
}

} // namespace yuzu::file_search
