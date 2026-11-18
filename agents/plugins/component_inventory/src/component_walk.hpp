/**
 * component_walk.hpp -- the bounded filesystem walk of the component_inventory plugin, and the
 * filesystem seam the scan and the OS legs build against.
 *
 * Pure header: no OS header, no filesystem library, no I/O of its own. Every directory listing and
 * every clock read goes through FsOps, so the unit test (tests/unit/test_component_walk.cpp) drives
 * the walk over an in-memory tree and a fake clock. The walk never opens a file: open_file is
 * declared here for the scan (which reads sizes, times and bytes from the opened file) and is never
 * called by walk().
 *
 * COMPLETENESS RULE. Nothing that hides rows may read as complete. WalkResult::stop is
 * Stop::complete only when no cause below occurred.
 *   Budget causes (budget_entries, budget_time, section_rows) end the walk at once.
 *   The other causes are recorded and the walk goes on, so an operator still sees what was reachable:
 *     depth           a directory deeper than max_depth was not listed
 *     dir_unreadable  a directory could not be listed
 *     dir_truncated   a listing was cut at max_dir_entries
 *     anchor_rows     an anchor produced more than max_rows_per_anchor candidates
 *   The FIRST cause recorded is the one reported.
 * There are no per-kind depth filters: max_depth is a backstop against pathological nesting, and
 * reaching it is an incomplete walk, never a silent cut (ADR-0028 Decision 4,
 * docs/adr/0028-agent-component-inventory-collection.md).
 *
 * MEMORY. The queue holds directory indices, not paths. Each directory queued gets one node (its
 * parent's index and its own name), and its path is rebuilt from the chain only when it is popped for
 * listing, so the cost of a queued directory is one name plus about 64 bytes (node and queue slot)
 * however deep it sits. The entry budget bounds the nodes: at most max_entries x (one name + about
 * 64 bytes), about 130 MB at the hostile worst (400,000 names of 255 bytes), a few MB on a real
 * tree. (A queued full path costs up to max_depth x 256 bytes, about 8 KiB, and the same bounds
 * would allow gigabytes.) The figure covers the queue and its nodes only: the candidates walk()
 * returns, and the scan's rows, are bounded by count (max_rows), not bytes, at up to max_rows full
 * paths of about max_depth x 256 bytes each.
 *
 * Paths are joined with '/': only the POSIX legs ship. No directory is excluded by name (an OSGi
 * container keeps its bundles in <product>/system, so such names are ordinary application directories).
 * Links and network mounts are never listed; each is counted in its own stat. Any other entry type is
 * skipped uncounted.
 *
 * ORDERED WALK. walk_ordered() (above walk()) is the sorted, depth-first, resumable walk of the
 * on-demand file search. It lists a directory, sorts the listing by name bytes, and visits every file
 * and directory entry through a caller-supplied visitor (the walk itself matches nothing and opens
 * nothing). A slice ends on a budget (time, entries, rows) with a file_search::Position naming the last
 * completed point, and the next slice resumes from that position by matching names against the real
 * listings; a changed directory identity restarts that subtree (duplicates possible, never a silent
 * skip). Every directory the walk could not search (a bound, a read failure, a mount, a device
 * change) is an OrderedGap, never a silent cut; links are skipped and counted, not followed, and
 * what a resume cannot see is listed under NOT DETECTED. The full rules sit on the declaration.
 */
#pragma once

#include "component_java_parsers.hpp"

#include <file_search_position.hpp>

#include <algorithm>
#include <chrono>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yuzu::component_inventory {

// ---- filesystem seam (names are binding: the scan and the OS legs are written against them) ----

struct DirEntry {
    enum class Type { file, dir, link, network_mount, other };
    std::string name;
    Type type{Type::other};
    std::uint64_t file_id{0}; // inode or file reference number; 0 = unknown
};

struct ListResult {
    std::vector<DirEntry> entries;
    bool error{false};     // the directory could not be listed
    bool truncated{false}; // the listing was cut at the cap the caller passed
    // Identity of the LISTED directory (0 = unknown): the device and the inode or file reference number.
    std::uint64_t dev{0};
    std::uint64_t file_id{0};
};

struct FileView {
    std::uint64_t size{0};
    std::int64_t mtime{0};
    // nullopt = I/O error; fewer bytes than asked only at end of file.
    std::function<std::optional<std::string>(std::uint64_t offset, std::size_t len)> read_at;
    // true while the open file still has the size and time it had when opened.
    std::function<bool()> unchanged;
};

struct FsOps {
    std::function<ListResult(const std::string& dir, std::size_t cap)> list;
    // nullopt = not opened: a link, not a regular file, refused or gone.
    std::function<std::optional<FileView>(const std::string& path)> open_file;
    std::function<std::chrono::steady_clock::time_point()> now;
};

// ---- policy ----

struct WalkLimits {
    std::size_t max_entries{400000};
    std::chrono::seconds max_wall{45}; // the scan turns this into the deadline it passes to walk()
    std::size_t max_rows_per_anchor{3000};
    std::size_t max_rows{20000};
    std::size_t max_depth{32};
    std::size_t max_dir_entries{50000};
};

struct Candidate {
    std::string path;
    std::string anchor_app; // first path component below the root
    std::size_t root{0};    // index of the root it was found under: an anchor's quota is per root
};

struct WalkStats {
    std::size_t entries{0};
    std::size_t links_skipped{0};
    std::size_t mounts_skipped{0};
};

// archive_unenumerated and archive_changed are set by the scan, never by the walk; the enum lives
// here so both share one vocabulary.
enum class Stop {
    complete,
    budget_entries,
    budget_time,
    anchor_rows,
    section_rows,
    depth,
    dir_unreadable,
    dir_truncated,
    archive_unenumerated,
    archive_changed,
};

[[nodiscard]] constexpr std::string_view to_token(Stop s) noexcept {
    switch (s) {
    case Stop::complete: return "complete";
    case Stop::budget_entries: return "budget_entries";
    case Stop::budget_time: return "budget_time";
    case Stop::anchor_rows: return "anchor_rows";
    case Stop::section_rows: return "section_rows";
    case Stop::depth: return "depth";
    case Stop::dir_unreadable: return "dir_unreadable";
    case Stop::dir_truncated: return "dir_truncated";
    case Stop::archive_unenumerated: return "archive_unenumerated";
    case Stop::archive_changed: return "archive_changed";
    }
    return "complete"; // unreachable for a valid enumerator
}

struct WalkResult {
    std::vector<Candidate> candidates;
    WalkStats stats;
    Stop stop{Stop::complete};
};

namespace walk_detail {

/// dir + '/' + name, with no doubled slash when `dir` already ends in one.
inline void append(std::string& dir, const std::string& name) {
    if (dir.empty() || dir.back() != '/')
        dir += '/';
    dir += name;
}

[[nodiscard]] inline std::string join(std::string dir, const std::string& name) {
    append(dir, name);
    return dir;
}

} // namespace walk_detail

// ---- ordered walk (the on-demand file search) ----

/// A place the ordered walk could not search: the path of the directory (or mount entry) and why.
struct OrderedGap {
    using Cause = yuzu::shared::file_search::GapCause;
    std::string path;
    Cause cause;
};

inline constexpr std::size_t kMaxOrderedGaps = 1000;
inline constexpr std::size_t kMaxOrderedRetainedBytes = 16 * 1024 * 1024;

struct OrderedResult {
    Stop stop{Stop::complete}; // complete, budget_time, budget_entries or section_rows only
    yuzu::shared::file_search::Position position; // the last completed point
    std::vector<OrderedGap> gaps;
    std::size_t gaps_dropped{0}; // gaps past kMaxOrderedGaps, counted not kept
    WalkStats stats;
    std::size_t rows{0};
    std::size_t retained_bytes_peak{0};
    bool advanced{false};  // position is later than the resume position, or the walk completed
    bool restarted{false}; // a changed directory identity restarted a subtree (or the root)
};

/// true = the visitor produced a row for this entry. `dir_dev` is the device of the listing of
/// `dir_path` (0 = unknown).
using OrderedVisit =
    std::function<bool(const std::string& dir_path, const DirEntry& entry, std::uint64_t dir_dev)>;

namespace walk_ordered_detail {

namespace fsr = yuzu::shared::file_search;
using Type = DirEntry::Type;
using Cause = OrderedGap::Cause;

using fsr::identity_changed; // the ONE identity rule (file_search_position.hpp)
using fsr::known;

class Walker {
public:
    Walker(const std::string& root, const fsr::Position& resume, const WalkLimits& limits, const FsOps& fs,
           std::chrono::steady_clock::time_point deadline, const OrderedVisit& visit,
           std::size_t max_retained)
        : root_(root), original_(resume), resume_(resume), limits_(limits), fs_(fs), deadline_(deadline),
          visit_(visit), max_retained_(max_retained),
          // A Position cannot name deeper than this, so nothing deeper is entered either.
          max_depth_(std::min(limits.max_depth, fsr::kMaxPositionDepth)) {
        stack_.reserve(max_depth_ + 1);
    }

    [[nodiscard]] OrderedResult run() {
        // A zero entry or row budget admits nothing: return the resume position itself without reading
        // a listing (re-reading the resume path could otherwise complete directories and report progress).
        if (limits_.max_entries == 0 || limits_.max_rows == 0) {
            out_.stop = limits_.max_entries == 0 ? Stop::budget_entries : Stop::section_rows;
            out_.position = original_;
            return std::move(out_);
        }
        const bool complete = walk_dir(root_, 0, nullptr);
        out_.position = moved_ ? fsr::Position{pos_root_dev_, pos_root_id_, stack_, after_} : original_;
        out_.advanced = complete || std::is_gt(fsr::walk_order(out_.position, original_));
        return std::move(out_);
    }

private:
    const std::string& root_;
    const fsr::Position& original_;
    fsr::Position resume_; // the position being resumed; blanked when the root is replaced
    const WalkLimits& limits_;
    const FsOps& fs_;
    std::chrono::steady_clock::time_point deadline_;
    const OrderedVisit& visit_;
    std::size_t max_retained_;
    std::size_t max_depth_;

    OrderedResult out_;
    std::vector<fsr::Frame> stack_; // the directories currently entered below the root
    std::string after_;             // last completed entry name in the innermost one
    // false until a step completes or a restart happens: a slice that ends before then returns the
    // resume position itself, so a stop while still re-reading the resume path never goes backwards.
    bool moved_{false};
    std::uint64_t root_dev_{0};
    std::uint64_t pos_root_dev_{0};
    std::uint64_t pos_root_id_{0};
    std::size_t retained_{0};

    [[nodiscard]] bool time_up() const { return fs_.now() >= deadline_; }

    bool stop(Stop s) {
        out_.stop = s;
        return false;
    }

    void add_gap(std::string path, Cause c) {
        if (out_.gaps.size() < kMaxOrderedGaps)
            out_.gaps.push_back({std::move(path), c});
        else
            ++out_.gaps_dropped;
    }

    // A listing that is not walked: one gap, the directory counts as completed.
    bool skip_dir(const std::string& path, Cause c) {
        add_gap(path, c);
        return true;
    }

    void complete(const std::string& name) {
        after_ = name;
        moved_ = true;
    }

    void restart() {
        out_.restarted = true;
        moved_ = true;
    }

    /// Walks the directory at `path`, `depth` below the root. `recorded` is its resume frame while it
    /// is still on the resume path (null for a directory reached fresh). true = the directory is
    /// completed (walked, or recorded as a gap); false = the slice ended inside it.
    bool walk_dir(const std::string& path, std::size_t depth, const fsr::Frame* recorded) {
        if (time_up())
            return stop(Stop::budget_time);
        ListResult lr = fs_.list(path, limits_.max_dir_entries);
        if (lr.error)
            return skip_dir(path, Cause::dir_unreadable);
        if (lr.truncated || lr.entries.size() > limits_.max_dir_entries)
            return skip_dir(path, Cause::dir_truncated);
        if (depth == 0)
            root_dev_ = lr.dev;
        else if (root_dev_ != 0 && lr.dev != 0 && lr.dev != root_dev_)
            return skip_dir(path, Cause::other_device);

        std::size_t charge = lr.entries.size() * sizeof(DirEntry);
        for (const auto& e : lr.entries)
            charge += e.name.size();
        if (charge > max_retained_ - retained_)
            return skip_dir(path, Cause::memory_cap);

        bool on_path = true;
        if (depth == 0) {
            if (identity_changed(resume_.root_dev, resume_.root_file_id, known(lr.dev, resume_.root_dev),
                                 known(lr.file_id, resume_.root_file_id))) {
                restart();
                resume_ = fsr::Position{}; // the whole root starts again
            }
            pos_root_dev_ = known(lr.dev, resume_.root_dev);
            pos_root_id_ = known(lr.file_id, resume_.root_file_id);
        } else {
            fsr::Frame& f = stack_.back();
            if (recorded != nullptr &&
                identity_changed(f.dev, f.file_id, known(lr.dev, f.dev), known(lr.file_id, f.file_id))) {
                restart();
                f.dev = lr.dev;
                f.file_id = lr.file_id;
                on_path = false; // the replaced subtree starts from its first entry
            } else {
                f.dev = known(lr.dev, f.dev);
                f.file_id = known(lr.file_id, f.file_id);
                on_path = recorded != nullptr;
            }
        }

        retained_ += charge;
        out_.retained_bytes_peak = std::max(out_.retained_bytes_peak, retained_);
        const bool done = walk_entries(path, depth, lr, on_path);
        retained_ -= charge;
        return done;
    }

    bool walk_entries(const std::string& path, std::size_t depth, ListResult& lr, bool on_path) {
        // Never trusted to arrive sorted; a repeated name keeps its first entry.
        std::stable_sort(lr.entries.begin(), lr.entries.end(),
                         [](const DirEntry& a, const DirEntry& b) { return a.name < b.name; });
        lr.entries.erase(std::unique(lr.entries.begin(), lr.entries.end(),
                                     [](const DirEntry& a, const DirEntry& b) { return a.name == b.name; }),
                         lr.entries.end());

        // On the resume path: the child to enter by name at this level, or (innermost level) the last
        // completed name to skip up to.
        const fsr::Frame* next = on_path && depth < resume_.dirs.size() ? &resume_.dirs[depth] : nullptr;
        const std::string* floor =
            on_path && depth == resume_.dirs.size() && !resume_.after.empty() ? &resume_.after : nullptr;

        for (const DirEntry& e : lr.entries) {
            if (e.name.empty() || e.name == "." || e.name == "..")
                continue;
            if (next != nullptr) {
                if (e.name < next->name)
                    continue;
                const fsr::Frame& want = *next;
                next = nullptr;
                if (e.name == want.name && e.type == Type::dir) {
                    if (!enter_resumed(path, depth, e.name, want))
                        return false;
                    continue;
                }
                // The name is missing or no longer a directory: the remaining frames are dropped and
                // this entry, the first one >= the name, is new.
            } else if (floor != nullptr && e.name <= *floor) {
                continue;
            }

            if (time_up())
                return stop(Stop::budget_time);
            if (out_.stats.entries >= limits_.max_entries)
                return stop(Stop::budget_entries);
            if (out_.rows >= limits_.max_rows)
                return stop(Stop::section_rows);
            ++out_.stats.entries;

            switch (e.type) {
            case Type::link: ++out_.stats.links_skipped; complete(e.name); continue;
            case Type::network_mount:
                ++out_.stats.mounts_skipped;
                add_gap(walk_detail::join(path, e.name), Cause::network_mount);
                complete(e.name);
                continue;
            case Type::other: complete(e.name); continue;
            case Type::dir:
            case Type::file: break;
            }

            if (visit_(path, e, lr.dev))
                ++out_.rows;
            const bool row_cap = out_.rows >= limits_.max_rows;

            if (e.type == Type::file) {
                complete(e.name);
            } else if (depth + 1 > max_depth_) {
                add_gap(walk_detail::join(path, e.name), Cause::depth);
                complete(e.name);
            } else {
                // Entered: from here the position is INSIDE the directory, at its start.
                stack_.push_back({e.name, 0, 0});
                after_.clear();
                moved_ = true;
                if (row_cap)
                    return stop(Stop::section_rows);
                if (!walk_dir(walk_detail::join(path, e.name), depth + 1, nullptr))
                    return false;
                stack_.pop_back();
                complete(e.name);
            }
            if (row_cap)
                return stop(Stop::section_rows);
        }
        return true;
    }

    // Enters a directory named by the resume position without visiting its entry a second time.
    bool enter_resumed(const std::string& path, std::size_t depth, const std::string& name,
                       const fsr::Frame& rec) {
        const std::string child = walk_detail::join(path, name);
        if (depth + 1 > max_depth_) {
            add_gap(child, Cause::depth);
        } else {
            stack_.push_back(rec);
            after_.clear();
            if (!walk_dir(child, depth + 1, &rec))
                return false;
            stack_.pop_back();
        }
        complete(name);
        return true;
    }
};

} // namespace walk_ordered_detail

/**
 * Sorted, depth-first, resumable walk of ONE root for the on-demand file search. A root is depth 0,
 * paths are joined with walk_detail::join, and open_file is never called. The walk matches no name or
 * pattern and reads no file: `visit` is called for every file and every directory entry (a directory
 * before it is descended into) and returns true when it produced a row. It never sleeps: the caller
 * paces from `visit` and from a wrapper around FsOps::list.
 *
 * LISTINGS. Every listing comes from fs.list(dir, limits.max_dir_entries) and is sorted by name bytes
 * here (never trusted to arrive sorted; a repeated name keeps its first entry). Entries that are empty,
 * "." or ".." are ignored; every other entry counts one in stats.entries. Links count links_skipped;
 * a network_mount counts mounts_skipped and adds a network_mount gap; any other type is skipped. A
 * listing with error is a dir_unreadable gap. A listing that is truncated or longer than
 * max_dir_entries is a dir_truncated gap and NONE of its entries is visited (a partial listing cannot
 * be resumed soundly and must not read as searched). A listing whose dev is non-zero and differs from
 * the root listing's non-zero dev is an other_device gap and none of its entries is visited. A
 * directory deeper than limits.max_depth (capped at file_search::kMaxPositionDepth, the deepest a
 * Position can name) is a depth gap; its entry is still visited. Gaps are capped at kMaxOrderedGaps,
 * further ones counted in gaps_dropped.
 *
 * BUDGETS. fs.now() >= deadline is checked before every listing AND before every entry's visit (one
 * clock read per entry: a visitor may be slow and a 50,000-entry flat listing must not carry a slice
 * past its deadline): Stop::budget_time. stats.entries >= limits.max_entries is checked before each new
 * entry: Stop::budget_entries. rows reaching limits.max_rows ends the slice immediately after the visit
 * that produced the last row: Stop::section_rows. A zero max_entries or max_rows admits nothing: the slice
 * returns `resume` itself, advanced false, without listing anything. Stop takes no other value; the other
 * causes are gaps.
 *
 * POSITION. position is the last completed point: dirs = the directories currently entered, each Frame
 * carrying that directory's name and the dev/file_id its listing reported, after = the last completed
 * entry name in the innermost one. A file, a link, a skipped entry and a directory recorded as a gap are
 * completed by their own step; an entered directory is completed only when its whole subtree is. So a
 * slice that ends after a directory's own visit and before its entries are consumed (the row cap on the
 * directory's own row, the deadline before its listing, the deadline or the entry budget before its
 * first entry) returns a position INSIDE that directory at its start: a Frame with its name, `after`
 * empty, and identity 0/0 when it has not been listed yet (unknown, so a resume can never report a false
 * restart). A slice that ends before any step completed returns `resume` itself.
 *
 * RESUME. Frames are matched by name against the sorted real listings: entries below the frame name are
 * skipped, an entry equal to it that is Type::dir is entered WITHOUT visiting its entry again, and in
 * the innermost directory entries with name <= after are skipped. When a name is missing or no longer a
 * directory the remaining frames are dropped and the walk continues with the first entry >= the name,
 * treated as new. A cursor name is never joined into a path that is listed unless that exact name
 * appeared as a Type::dir entry of the parent's real listing in this call. When a frame and its listing
 * both carry a non-zero identity and differ (the directory was replaced), or a non-zero
 * resume.root_dev/root_file_id differs from the root listing's, `restarted` is set and that subtree (or
 * the root) starts from its first entry: duplicates are possible, a silent skip is not. Unknown (zero)
 * identities never trigger a restart. Listings re-read on the resume path are NOT charged to
 * max_entries (only entries after the resume point are), so a deep resume cannot exhaust the budget
 * before progressing. `advanced` is true when the returned position is later than `resume` in
 * file_search::walk_order or the walk completed. A slice with restarted false NEVER returns a position
 * earlier than `resume`; a restart may. A slice that ends with advanced false and restarted false is a
 * stall (the caller's governor counts it).
 *
 * NOT DETECTED. Resume goes by name and by the identity of the directories on the resume path, so a
 * change between slices that moves neither is not seen and leaves no gap: an entry added at or before
 * the resume point of a directory that kept its identity, a completed directory swapped for another of
 * the same name, and a replacement that reports the same identity as the directory it replaced (a
 * filesystem may reuse one) or reports none, or the directory it replaced had reported none. Such
 * entries are not visited. A walk of more than one slice is not a snapshot.
 *
 * MEMORY. The sorted listings of the directories currently entered are held and the entry budget does
 * NOT bound them (descending through first children counts one entry per level while every level holds
 * a full listing: 32 levels of 50,000 names with the defaults). Each held listing is charged the sum of
 * its name bytes plus entries * sizeof(DirEntry), and the charge is returned when the walk leaves the
 * directory. A directory (the root included, and one re-entered on the resume path) whose listing would
 * take the total over `max_retained_bytes` is not entered: a memory_cap gap, none of its entries is
 * visited, and the walk continues with its next sibling. With the default 50,000-entry listing cap and
 * 255-byte names one listing is about 15 MiB, so a single directory always fits and the cap bites only
 * on a chain of very large ancestors. retained_bytes_peak reports the high-water mark.
 * The cap bounds what is HELD, not peak live memory: a listing is live before it is charged (one a
 * memory_cap gap then rejects included) and the sort takes scratch, so allow about one more listing.
 */
[[nodiscard]] inline OrderedResult
walk_ordered(const std::string& root, const yuzu::shared::file_search::Position& resume,
             const WalkLimits& limits, const FsOps& fs, std::chrono::steady_clock::time_point deadline,
             const OrderedVisit& visit, std::size_t max_retained_bytes = kMaxOrderedRetainedBytes) {
    return walk_ordered_detail::Walker(root, resume, limits, fs, deadline, visit, max_retained_bytes).run();
}

/**
 * Walk `roots` breadth-first through `fs`. A root is depth 0. `deadline` is computed once by the
 * caller (the scan reuses the same instant for its archive reads); it and the entry budget are
 * checked before every directory is listed, i.e. after the previous one finished, and the entry
 * budget is also enforced entry by entry so stats.entries never exceeds limits.max_entries.
 */
[[nodiscard]] inline WalkResult walk(std::span<const std::string> roots, const WalkLimits& limits,
                                     const FsOps& fs, std::chrono::steady_clock::time_point deadline) {
    using Type = DirEntry::Type;
    WalkResult out;

    // First cause wins; a budget cause additionally ends the walk (the caller returns at once).
    const auto record = [&out](Stop s) {
        if (out.stop == Stop::complete)
            out.stop = s;
    };

    constexpr std::size_t kNoNode = static_cast<std::size_t>(-1);
    // One per directory queued under the current root: its parent and its own name (the root's name is
    // the root path as given). Pending refers to these by index.
    struct Node {
        std::size_t parent;
        std::string name;
    };
    struct Pending {
        std::size_t node;
        std::size_t depth;
        std::size_t anchor; // the depth-1 ancestor's node, kNoNode for the root itself
    };
    static_assert(std::is_trivially_copyable_v<Pending>,
                  "a queue slot holds indices only; a queued path brings back the per-entry full-path cost");

    for (std::size_t root_index = 0; root_index < roots.size(); ++root_index) {
        std::unordered_map<std::string, std::size_t> anchor_rows; // per root
        std::vector<Node> nodes;
        std::deque<Pending> queue;
        nodes.push_back({kNoNode, roots[root_index]});
        queue.push_back({0, 0, kNoNode});

        // The directory's path, root first. Appended in place: one pass over the final length.
        const auto path_of = [&nodes](std::size_t node) {
            std::vector<std::size_t> chain; // leaf first
            for (; node != kNoNode; node = nodes[node].parent)
                chain.push_back(node);
            std::string path = nodes[chain.back()].name;
            for (auto it = chain.rbegin() + 1; it != chain.rend(); ++it)
                walk_detail::append(path, nodes[*it].name);
            return path;
        };

        while (!queue.empty()) {
            if (fs.now() >= deadline) {
                record(Stop::budget_time);
                return out;
            }
            const Pending cur = queue.front();
            queue.pop_front();

            const std::string cur_path = path_of(cur.node);
            ListResult listing = fs.list(cur_path, limits.max_dir_entries);
            if (listing.error) {
                record(Stop::dir_unreadable);
                continue;
            }
            if (listing.truncated || listing.entries.size() > limits.max_dir_entries)
                record(Stop::dir_truncated);
            const std::size_t n = std::min(listing.entries.size(), limits.max_dir_entries);

            for (std::size_t i = 0; i < n; ++i) {
                const DirEntry& e = listing.entries[i];
                if (e.name.empty() || e.name == "." || e.name == "..")
                    continue;
                if (out.stats.entries >= limits.max_entries) {
                    record(Stop::budget_entries);
                    return out;
                }
                ++out.stats.entries;

                switch (e.type) {
                case Type::link: ++out.stats.links_skipped; continue;
                case Type::network_mount: ++out.stats.mounts_skipped; continue;
                case Type::other: continue;
                case Type::dir: {
                    if (cur.depth + 1 > limits.max_depth) {
                        record(Stop::depth);
                        continue;
                    }
                    nodes.push_back({cur.node, e.name});
                    queue.push_back({nodes.size() - 1, cur.depth + 1,
                                     cur.anchor == kNoNode ? nodes.size() - 1 : cur.anchor});
                    continue;
                }
                case Type::file: break;
                }

                if (!is_java_archive_name(e.name))
                    continue;
                const std::string& anchor = cur.anchor == kNoNode ? e.name : nodes[cur.anchor].name;
                std::size_t& rows = anchor_rows[anchor];
                if (rows >= limits.max_rows_per_anchor) {
                    record(Stop::anchor_rows);
                    continue;
                }
                if (out.candidates.size() >= limits.max_rows) {
                    record(Stop::section_rows);
                    return out;
                }
                ++rows;
                out.candidates.push_back({walk_detail::join(cur_path, e.name), anchor, root_index});
            }
        }
    }
    return out;
}

} // namespace yuzu::component_inventory
