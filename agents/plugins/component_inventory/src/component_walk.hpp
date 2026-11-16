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
 */
#pragma once

#include "component_java_parsers.hpp"

#include <algorithm>
#include <chrono>
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
};

struct ListResult {
    std::vector<DirEntry> entries;
    bool error{false};     // the directory could not be listed
    bool truncated{false}; // the listing was cut at the cap the caller passed
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
