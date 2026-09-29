#pragma once

/**
 * confined_fs_walk.hpp -- PURE, header-only, Ops-parameterised iterative
 * walker for confined recursive delete (PLAN-010: centralises the semantics
 * PLAN-001/002/014 bind, so both platform legs -- and their sight-unseen
 * authors -- share ONE walk implementation instead of two hand-copies that
 * drift). No OS headers: only confined_fs_rules.hpp plus <optional>,
 * <utility>, <vector>, <string>.
 *
 * `Ops` is a compile-time interface (duck-typed template parameter, no
 * virtual dispatch) a platform shell provides:
 *
 *   using DirHandle = /-- move-only handle type (fd, HANDLE, whatever) --/;
 *   OpenDirRes<DirHandle> open_dir(DirHandle& parent, const std::string& name);
 *   EnumerateResult enumerate(DirHandle& dir, const EnumBudget&);
 *   UnlinkOutcome unlink(DirHandle& parent, const std::string& name, UnlinkKind,
 *                        std::uint64_t max_bytes_remaining);
 *   std::chrono::steady_clock::time_point now();
 *
 * `walk_delete` itself never opens a path, never resolves a symlink, and
 * never allocates OS resources -- it only calls the four `Ops` members above
 * and asks `decide_entry` what to do with what they return. A test TU can
 * therefore drive it end-to-end with a fake in-memory `Ops` and zero
 * disk access (test_confined_fs_walk.cpp).
 *
 * ── Binding walker semantics ─────────────────────────────────────────────
 *
 *  1. `deadline = ops.now() + limits.max_wall` (SATURATING -- an extreme
 *     max_wall clamps to time_point::max rather than overflowing) is
 *     computed EXACTLY ONCE, at
 *     the start of the walk -- never re-derived per directory or per entry
 *     (a re-derived deadline would let the wall-time cap creep forward
 *     indefinitely on a slow walk).
 *  2. Traversal is an EXPLICIT ITERATIVE STACK of `{DirHandle, rel_prefix,
 *     depth}` frames -- no recursion, so a deep/adversarial directory tree
 *     cannot blow the call stack. The root frame is depth 0.
 *  3. Each directory is enumerated with
 *     `EnumBudget{max_entries - tally.entries_seen (0 if already exhausted),
 *     deadline}`.
 *       - Enumeration truncated with `WallTimeCap`: stop IMMEDIATELY --
 *         the entries collected before truncation are NOT processed --
 *         `stop_reason = WallTimeCap`.
 *       - Enumeration truncated with `EntryCap`: the entries it DID
 *         return are processed normally, and the walk then stops with
 *         `stop_reason = EntryCap`. This holds whether the truncated
 *         batch was empty or not -- a directory larger than the budget
 *         must never report `stop_reason = None`, which a caller is
 *         entitled to read as "the tree was exhaustively visited".
 *       - `EnumerateResult::reason == OsError`: append
 *         `EntryOutcome{<this dir's rel_path>, Failed, OsError, os_error}`
 *         and continue on to the NEXT sibling on the stack (the walk is
 *         not stopped by one unreadable directory) -- but the walk REMEMBERS
 *         that a subtree went unvisited and reports `OsError` as its
 *         `stop_reason` at the end rather than `None`, which would claim an
 *         exhaustive visit.
 *  4. Per collected entry, in order:
 *       - `stat_error != 0` -> append `Failed(OsError, stat_error)`,
 *         `entries_seen++`, continue to the next entry.
 *       - `name_invalid` -> append `Skipped(InvalidName)`, `entries_seen++`,
 *         continue (never reaches match or deletion).
 *       - Otherwise, the LAZY MATCH protocol (PLAN-001): call
 *         `decide_entry` first with `name_matched = true`. `MatchFn` is
 *         called ONLY if that decision's rule sits AT OR AFTER the
 *         name-match rule in the binding order -- i.e. the resulting
 *         action is `Unlink`, or `SkipEntry` with `reason == ByteCap`
 *         (both rules that fire strictly after the name-match check). Any
 *         other outcome (a structural rejection, a cap stop) means
 *         `decide_entry` never needed `name_matched` at all, so `MatchFn`
 *         is never invoked for it. When the real match is needed, it is
 *         evaluated inside a try/catch: a throw sets
 *         `stop_reason = MatchError` and returns the PARTIAL result built
 *         so far. Otherwise `decide_entry` is re-invoked with the real
 *         `name_matched` value and the walker acts on THAT decision.
 *  5. Acting on the (possibly re-evaluated) decision:
 *       - `Unlink`: call `ops.unlink(parent, name, File, remaining byte
 *         budget)` -- the leg RE-MEASURES the entry immediately before
 *         deleting and returns `Skipped(ByteCap)` if the live size would
 *         breach the budget; append
 *         `Deleted` or `Failed(reason, os_error)` per the outcome;
 *         `entries_seen++` always; `bytes_deleted += outcome.bytes` (the
 *         size the leg MEASURED, not the enumerated one) ONLY on a
 *         successful delete.
 *       - `RecurseIntoDir`: call `ops.open_dir`. A POLICY refusal
 *         (`SymlinkRejected`/`ReparseRejected`/`DeviceBoundary`/
 *         `NotRegularFile`/`InvalidName`) appends `Skipped(reason)`; an
 *         `OsError` refusal appends `Failed(OsError, os_error)`
 *         (PLAN-002); success pushes a new stack frame. `entries_seen++`
 *         either way.
 *       - `SkipEntry`: `entries_seen++`; append an outcome UNLESS
 *         `reason == NameFilteredOut`, which is intentionally left
 *         UNRECORDED (bounded-output rule -- a filtered-out tree must not
 *         blow up `DeleteResult::entries` to the size of the whole subtree)
 *         but IS still counted in `entries_seen`.
 *       - `StopWalk`: `stop_reason = reason`; return immediately.
 *  6. Directories are TRAVERSED, never deleted -- `RecurseIntoDir` never
 *     reaches `ops.unlink`. `rel_path` components are joined with `/`.
 *  7. EXCEPTION FIREWALL (PLAN-014): the entire walk body runs inside one
 *     outer try/catch(...). Any exception that is not the deliberately
 *     caught `MatchFn` throw (rule 4) is caught here, `stop_reason` is set
 *     to `Internal`, and the best-effort partial result built so far is
 *     returned. `walk_delete` lets NO exception escape to its caller.
 */

#include <yuzu/agent/confined_fs_rules.hpp>

#include <chrono>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::agent::confined_fs {

/// Result of an `Ops::open_dir` call: either a handle to the newly opened
/// directory, or a refusal reason (`Reason::None` + a present `handle` is
/// success; any other `reason` is a refusal and `handle` is empty).
template <class H>
struct OpenDirRes {
    std::optional<H> handle;
    Reason reason{Reason::None};
    int os_error{0};
};

namespace detail {

/// One frame of the explicit traversal stack.
template <class DirHandle>
struct WalkFrame {
    DirHandle handle;
    std::string rel_prefix; // "" for the root, else "a/b" with a trailing entry name to append
    std::uint32_t depth;
};

/// The refusal reasons that mean "this entry was deliberately declined by
/// policy" -- the walk records them and continues. Any OTHER refusal means the
/// subtree was not traversed for a reason the walk cannot treat as a decision,
/// and must stop it instead of silently completing.
///
/// This predicate answers CONTINUE-VS-STOP. It is NOT the complete-vs-incomplete
/// question, which `note_outcome` below answers, and the two lists deliberately
/// do not match: `DepthCap` appears here (a depth refusal does not stop the
/// walk) AND in `note_outcome`'s incomplete set (a subtree went unvisited, so
/// the walk is not complete). Both are correct simultaneously. Do not
/// "harmonise" them -- they are answers to different questions, and making
/// either list mirror the other reintroduces one of the two defect shapes this
/// file exists to prevent.
///
/// `DepthCap` is currently unreachable through this predicate: it arrives via
/// `Action::SkipEntry` (confined_fs_rules.hpp rule 6), never as an `open_dir`
/// refusal reason from either platform shell. It is listed defensively so a
/// shell that does start reporting it cannot accidentally stop the walk.
constexpr bool is_policy_refusal(Reason r) {
    return r == Reason::SymlinkRejected || r == Reason::ReparseRejected ||
           r == Reason::DeviceBoundary || r == Reason::NotRegularFile ||
           r == Reason::InvalidName || r == Reason::DepthCap;
}

inline std::string join_rel(const std::string& prefix, const std::string& name) {
    if (prefix.empty())
        return name;
    return prefix + "/" + name;
}

} // namespace detail

/**
 * Walk `root` (already-open, caller-owned) deleting every entry `match`
 * accepts, subject to `limits`. See the header banner for the full binding
 * semantics. Never throws -- see rule 7 above.
 */
template <class Ops>
DeleteResult walk_delete(typename Ops::DirHandle root, Ops& ops, const MatchFn& match,
                          const DeleteLimits& limits) {
    using DirHandle = typename Ops::DirHandle;

    DeleteResult result{};
    result.stop_reason = Reason::None;

    // `stop_reason == None` is a CONTRACT. State it precisely, because the
    // loose phrasing ("a walk that skipped anything never reports None") is
    // WRONG in a way that matters to a successor: it would make every symlink
    // refusal an incomplete walk, which is the opposite of what a policy
    // refusal means. The contract is:
    //
    //   None == every entry was VISITED, and every entry that this walk was
    //           supposed to act on was acted on. A deliberate policy refusal
    //           counts as acted on; a budget that stopped us does not.
    //
    // Six separate defects in this file were the same shape -- some path left
    // work undone while None was still reported -- so this is derived from the
    // OUTCOMES rather than from a list of causes that has to be extended every
    // time a new one appears. Incomplete:
    //   * any Failed outcome            -- an action did not happen
    //   * a DepthCap skip               -- a subtree was never visited
    //   * a ByteCap skip                -- an entry we SELECTED went undeleted
    //   * enumerate/open_dir OsError    -- a subtree was never visited
    //
    // ByteCap is in that list and the other policy reasons are not, and the
    // distinction is the whole point: ByteCap is a BUDGET, exactly like
    // DepthCap. The entry matched, we intended to delete it, and a limit
    // stopped us -- and because the budget does not replenish, every later
    // match is skipped too, so a byte-exhausted walk can silently do nothing
    // for its entire remaining traversal. SymlinkRejected, ReparseRejected,
    // DeviceBoundary, NotRegularFile and InvalidName are REFUSALS: the walker
    // looked at the entry and declined it on purpose, which is a completed
    // visit and must not read as incomplete. NameFilteredOut never reaches an
    // outcome at all.
    //
    // Recording `incomplete` centrally, at the one place outcomes are appended,
    // is what stops a seventh instance.
    Reason incomplete = Reason::None;
    const auto note_outcome = [&incomplete](const EntryOutcome& o) {
        if (incomplete != Reason::None)
            return; // first cause wins
        if (o.status == EntryStatus::Failed)
            incomplete = o.reason == Reason::None ? Reason::OsError : o.reason;
        else if (o.status == EntryStatus::Skipped &&
                 (o.reason == Reason::DepthCap || o.reason == Reason::ByteCap))
            incomplete = o.reason;
    };

    try {
        // B005: saturate rather than overflow. `now() + max_wall` is signed
        // chrono arithmetic, so an extreme caller-supplied max_wall is UB and
        // can wrap to a deadline in the PAST -- the opposite of failing closed
        // for a cap whose whole job is to bound the walk.
        const auto now0 = ops.now();
        const auto headroom = std::chrono::steady_clock::time_point::max() - now0;
        const auto capped_wall =
            (limits.max_wall > std::chrono::duration_cast<std::chrono::milliseconds>(headroom))
                ? std::chrono::duration_cast<std::chrono::milliseconds>(headroom)
                : limits.max_wall;
        const auto deadline = now0 + capped_wall;

        std::vector<detail::WalkFrame<DirHandle>> stack;
        stack.push_back(detail::WalkFrame<DirHandle>{std::move(root), std::string{}, 0});

        while (!stack.empty()) {
            detail::WalkFrame<DirHandle> frame = std::move(stack.back());
            stack.pop_back();

            const std::uint64_t remaining = result.tally.entries_seen >= limits.max_entries
                                                 ? 0
                                                 : limits.max_entries - result.tally.entries_seen;
            EnumBudget budget{remaining, deadline};

            EnumerateResult enum_result = ops.enumerate(frame.handle, budget);

            if (enum_result.reason == Reason::WallTimeCap) {
                result.stop_reason = Reason::WallTimeCap;
                return result;
            }
            if (enum_result.reason == Reason::OsError) {
                {
                        const EntryOutcome oc = EntryOutcome{frame.rel_prefix, EntryStatus::Failed,
                                                        Reason::OsError, enum_result.os_error};
                        note_outcome(oc);
                        result.entries.push_back(oc);
                    }
                if (incomplete == Reason::None)
                    incomplete = Reason::OsError; // subtree unvisited -- see C001 above
                continue; // move on to sibling directories still on the stack
            }
            // Any OTHER non-None reason means enumeration did not complete for a
            // reason this walker does not have a specific policy for -- today
            // Reason::Internal from a platform shell's own exception firewall.
            // Stop and report it. This is deliberately a catch-all rather than a
            // list: an unhandled reason previously fell through every branch and
            // silently truncated the directory while reporting stop_reason None,
            // which a caller reads as "exhaustively visited". EntryCap is absent
            // here ON PURPOSE -- its batch must be processed first, so it is
            // handled after the entry loop below.
            if (enum_result.reason != Reason::None && enum_result.reason != Reason::EntryCap) {
                result.stop_reason = enum_result.reason;
                return result;
            }

            bool stopped = false;
            for (auto& dir_entry : enum_result.entries) {
                const std::string rel_path = detail::join_rel(frame.rel_prefix, dir_entry.name);

                if (dir_entry.stat_error != 0) {
                    {
                        const EntryOutcome oc = EntryOutcome{
                        rel_path, EntryStatus::Failed, Reason::OsError, dir_entry.stat_error};
                        note_outcome(oc);
                        result.entries.push_back(oc);
                    }
                    ++result.tally.entries_seen;
                    continue;
                }
                if (dir_entry.name_invalid) {
                    {
                        const EntryOutcome oc = EntryOutcome{rel_path, EntryStatus::Skipped, Reason::InvalidName, 0};
                        note_outcome(oc);
                        result.entries.push_back(oc);
                    }
                    ++result.tally.entries_seen;
                    continue;
                }

                const bool deadline_exceeded = ops.now() >= deadline;
                const bool depth_exceeded = frame.depth >= limits.max_depth;

                // Lazy-match protocol (PLAN-001): probe with name_matched=true
                // first; only call the real MatchFn if the probe decision's
                // rule sits at or after the name-match rule.
                Decision decision = decide_entry(dir_entry.meta, limits, result.tally,
                                                  deadline_exceeded, depth_exceeded,
                                                  /*name_matched=*/true);
                const bool needs_real_match =
                    decision.action == Action::Unlink ||
                    (decision.action == Action::SkipEntry && decision.reason == Reason::ByteCap);
                if (needs_real_match) {
                    bool matched = false;
                    try {
                        matched = match(rel_path, dir_entry.meta);
                    } catch (...) {
                        result.stop_reason = Reason::MatchError;
                        stopped = true;
                        break;
                    }
                    decision = decide_entry(dir_entry.meta, limits, result.tally,
                                             deadline_exceeded, depth_exceeded, matched);
                }

                switch (decision.action) {
                case Action::Unlink: {
                    // Hand the leg the REMAINING byte budget so it can re-measure
                    // the entry immediately before deleting it and refuse a swap
                    // that would breach the cap. decide_entry's check used the
                    // size seen during enumeration, which an attacker controlling
                    // the tree can invalidate before we act.
                    const std::uint64_t budget_left =
                        limits.max_bytes > result.tally.bytes_deleted
                            ? limits.max_bytes - result.tally.bytes_deleted
                            : 0;
                    UnlinkOutcome outcome = ops.unlink(frame.handle, dir_entry.name,
                                                       UnlinkKind::File, budget_left);
                    if (outcome.status == EntryStatus::Deleted)
                        result.tally.bytes_deleted += outcome.bytes;
                    {
                        const EntryOutcome oc = EntryOutcome{rel_path, outcome.status, outcome.reason, outcome.os_error};
                        note_outcome(oc);
                        result.entries.push_back(oc);
                    }
                    ++result.tally.entries_seen;
                    break;
                }
                case Action::RecurseIntoDir: {
                    // S1: bound concurrently-open handles. The stack holds one
                    // per pending subdirectory, so without this the descriptor
                    // cost is bounded only by max_entries and is paid
                    // process-wide, not by this walk alone.
                    // +2, measured: the popped frame still owns its handle and
                    // the handle we are about to open would be live, so peak
                    // concurrent handles is stack.size() + 2. Counting frames
                    // alone overshot the documented bound by exactly that much.
                    //
                    // Checked BEFORE the open, not after. Opening first and
                    // refusing on the result would make the refusal path itself
                    // hold max_open_dirs + 1 handles for the window between the
                    // open and the return -- one over the bound this exists to
                    // enforce, on the very path that reports the bound was hit.
                    if (stack.size() + 2 > limits.max_open_dirs) {
                        ++result.tally.entries_seen;
                        result.stop_reason = Reason::OpenDirCap;
                        return result;
                    }
                    OpenDirRes<DirHandle> opened = ops.open_dir(frame.handle, dir_entry.name);
                    ++result.tally.entries_seen;
                    if (opened.handle.has_value()) {
                        stack.push_back(detail::WalkFrame<DirHandle>{
                            std::move(*opened.handle), rel_path,
                            frame.depth + 1});
                    } else if (opened.reason == Reason::OsError) {
                        {
                        const EntryOutcome oc = EntryOutcome{
                            rel_path, EntryStatus::Failed, Reason::OsError, opened.os_error};
                        note_outcome(oc);
                        result.entries.push_back(oc);
                    }
                        if (incomplete == Reason::None)
                            incomplete = Reason::OsError; // subtree unvisited -- C001
                    } else if (detail::is_policy_refusal(opened.reason)) {
                        {
                        const EntryOutcome oc = EntryOutcome{rel_path, EntryStatus::Skipped, opened.reason, 0};
                        note_outcome(oc);
                        result.entries.push_back(oc);
                    }
                    } else {
                        // NOT a policy refusal -- the subtree was never traversed for
                        // a reason that is not "we deliberately declined this entry"
                        // (today Reason::Unsupported, when the platform primitive is
                        // unavailable at all). Recording it as a Skipped entry and
                        // continuing would let the walk finish with stop_reason None,
                        // which a caller reads as exhaustively visited. Whitelist the
                        // real refusals and stop on everything else.
                        {
                        const EntryOutcome oc = EntryOutcome{rel_path, EntryStatus::Failed, opened.reason,
                                         opened.os_error};
                        note_outcome(oc);
                        result.entries.push_back(oc);
                    }
                        result.stop_reason = opened.reason;
                        return result;
                    }
                    break;
                }
                case Action::SkipEntry:
                    ++result.tally.entries_seen;
                    if (decision.reason != Reason::NameFilteredOut) {
                        {
                        const EntryOutcome oc = EntryOutcome{rel_path, EntryStatus::Skipped, decision.reason, 0};
                        note_outcome(oc);
                        result.entries.push_back(oc);
                    }
                    }
                    break;
                case Action::StopWalk:
                    result.stop_reason = decision.reason;
                    stopped = true;
                    break;
                }

                if (stopped)
                    break;
            }

            if (stopped)
                return result;

            // The entry budget truncated this directory's listing. Whatever it did
            // return has now been processed, but the directory was NOT fully
            // enumerated, so the walk must report the cap rather than complete
            // silently — a caller that sees stop_reason None is entitled to treat
            // the tree as exhaustively visited. This is the single EntryCap exit:
            // an empty truncated batch simply falls through the loop to here.
            if (enum_result.reason == Reason::EntryCap) {
                result.stop_reason = Reason::EntryCap;
                return result;
            }
        }

        // Nothing stopped the walk, but if a subtree was skipped the walk was
        // NOT exhaustive and must not claim it was.
        if (result.stop_reason == Reason::None)
            result.stop_reason = incomplete;
        return result;
    } catch (...) {
        result.stop_reason = Reason::Internal;
        return result;
    }
}

} // namespace yuzu::agent::confined_fs
