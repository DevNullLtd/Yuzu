#pragma once

/**
 * component_pkg_scan.hpp -- the `python` and `node` actions of the component_inventory plugin:
 * installed Python distributions (a `METADATA` file inside `<name>-<version>.dist-info`, a `PKG-INFO`
 * inside `*.egg-info`, or a single-file `*.egg-info`) and Node packages (`package.json` of a package
 * under `node_modules`).
 *
 * Portable: no OS header. Like scan() and scan_native() it goes through the FsOps seam, so the unit
 * test drives it over an in-memory tree and a fake clock. The pure readers are
 * component_python_parsers.hpp and component_node_parsers.hpp.
 *
 * SAME DISCIPLINE AS scan() (component_scan.hpp): one deadline computed once and checked between files
 * and once more at the end; one open per candidate, one read_at through that FileView, an unchanged()
 * check after it; the same completeness rule. What differs:
 *  - candidates are metadata file names (WalkPolicy::is_candidate), and a candidate whose path does not
 *    have the shape of a real owner (a METADATA outside any `.dist-info`, a package.json outside
 *    `node_modules/<pkg>`) is dropped before anything is opened;
 *  - the walk prunes package source trees by policy (WalkPolicy::skip_dir): the contents of a
 *    site-packages / dist-packages directory other than the metadata directories, and everything below
 *    a node package other than its own node_modules. Pruning is the design of these two actions, not a
 *    gap, so the pure scan reports the count in WalkStats::dirs_excluded as the walk contract requires
 *    and the DISPATCH (answer_pkg below) hands it to a logger and clears it before the answer is built:
 *    `package_tree_skipped` means package-owned trees on `native` and is never emitted here;
 *  - a metadata file that cannot be read in full (or parsed) is an item-level gap, never a constraint:
 *    the row exists with version_source `unreadable` (python: `filename` when the directory name
 *    carries the version) and the scan stays complete. A file that changes between open and read is
 *    handled as the Java scan handles a changed archive: its row stays, Stop::archive_changed.
 *
 * Bounds: python reads at most the first 16 KiB of a metadata file; node reads at most 64 KiB + 1
 * byte of a package.json (the extra byte is what makes an oversized file detectable). Both reads are
 * one read_at. Nothing is executed and no link is followed (the leg's FsOps guarantees the latter).
 */

#include "component_node_parsers.hpp"
#include "component_python_parsers.hpp"
#include "component_scan.hpp"
#include "component_walk.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace yuzu::component_inventory {

inline constexpr std::string_view kPythonAction = "python";
inline constexpr std::string_view kNodeAction = "node";

namespace pkg_detail {

inline constexpr std::string_view kSitePackages = "site-packages";
inline constexpr std::string_view kDistPackages = "dist-packages";

/// The leaf of the parent directory of `dir_path`: "" when it has none.
[[nodiscard]] inline std::string_view parent_leaf(std::string_view dir_path) noexcept {
    const auto i = dir_path.rfind('/');
    if (i == std::string_view::npos || i == 0)
        return {};
    return scan_detail::leaf_of(dir_path.substr(0, i));
}

[[nodiscard]] inline bool node_is_candidate(std::string_view leaf) noexcept {
    return leaf == "package.json";
}

} // namespace pkg_detail

/// Python: the metadata file names are the candidates. A directory directly inside site-packages or
/// dist-packages is pruned unless it is a `.dist-info` / `.egg-info` directory, so an installed
/// package's source tree is never listed.
[[nodiscard]] inline WalkPolicy python_policy() {
    WalkPolicy p;
    p.is_candidate = &is_python_metadata_leaf;
    p.skip_dir = [](const std::string& dir) {
        const auto parent = pkg_detail::parent_leaf(dir);
        if (parent != pkg_detail::kSitePackages && parent != pkg_detail::kDistPackages)
            return false;
        const auto leaf = scan_detail::leaf_of(dir);
        return !leaf.ends_with(".dist-info") && !leaf.ends_with(".egg-info");
    };
    return p;
}

/// Node: `package.json` files are the candidates; node_dir_prunable decides which trees are never
/// listed (a package's own sources, `.bin`, anything nested past kMaxNodeNesting node_modules).
[[nodiscard]] inline WalkPolicy node_policy() {
    WalkPolicy p;
    p.is_candidate = &pkg_detail::node_is_candidate;
    p.skip_dir = [](const std::string& dir) { return node_dir_prunable(dir); };
    return p;
}

/// The python action's bounds: the scan's, with a depth of 8 (a virtualenv under /opt sits about six
/// directories below its root).
[[nodiscard]] inline WalkLimits python_limits() {
    WalkLimits l;
    l.max_depth = 8;
    return l;
}

namespace pkg_detail {

/**
 * The shared body: walk under `policy`, keep the candidates `keep(path)` accepts, and for each read at
 * most `read_cap` bytes through the one open FileView and let `fill(path, bytes, row)` set name,
 * version and version_source. `bytes` is nullopt when the file could not be opened or read in full.
 */
template <class Keep, class Fill>
[[nodiscard]] inline ScanResult scan_pkg(std::string_view kind, std::span<const std::string> roots,
                                         const WalkLimits& limits, const FsOps& fs, const WalkPolicy& policy,
                                         std::size_t read_cap, Keep&& keep, Fill&& fill) {
    ScanResult out;
    const auto started = fs.now();
    const auto deadline = started + limits.max_wall;

    WalkResult walked = walk(roots, limits, fs, deadline, policy);
    out.stats = walked.stats;
    out.stop = walked.stop;
    const auto record = [&out](Stop s) {
        if (out.stop == Stop::complete)
            out.stop = s;
    };

    // At most one row per candidate, and the walk already holds its candidates to the section and
    // per-anchor caps: this loop keeps no quota of its own. The caps therefore count candidates
    // before `keep` runs (the walk sees only the leaf name), so same-named files of the wrong shape
    // use the quota and a noisy tree can end `anchor_rows` or `section_rows` with fewer rows than
    // the cap; the answer is still honestly constrained.
    for (const auto& c : walked.candidates) {
        if (fs.now() >= deadline) {
            record(Stop::budget_time);
            break;
        }
        if (!keep(c.path))
            continue; // not the shape of a real owner: nothing is opened

        Row row;
        row.kind = std::string(kind);
        row.path = c.path;
        row.anchor_app = c.anchor_app;

        std::optional<std::string> bytes;
        if (const auto fv = fs.open_file(c.path)) {
            row.size = fv->size;
            row.mtime = fv->mtime;
            const auto len = static_cast<std::size_t>(std::min<std::uint64_t>(fv->size, read_cap));
            bytes = len == 0 ? std::optional<std::string>{std::string{}}
                             : scan_detail::read_exact(*fv, 0, len);
            if (!fv->unchanged())
                record(Stop::archive_changed);
        }
        fill(c.path, bytes, row);
        if (row.version_source == kSourceUnreadable)
            ++out.version_unreadable;
        out.rows.push_back(std::move(row));
    }

    const auto finished = fs.now();
    if (finished >= deadline)
        record(Stop::budget_time);
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(finished - started).count();
    out.elapsed_ms = elapsed > 0 ? static_cast<std::uint64_t>(elapsed) : 0;
    return out;
}

} // namespace pkg_detail

/**
 * Walk `roots` for Python distributions: one row per `METADATA` (in `<n>-<v>.dist-info`), `PKG-INFO`
 * (in `*.egg-info`) or single-file `*.egg-info`. kind `python`; version_source is the parser's:
 * metadata | filename | unreadable.
 */
[[nodiscard]] inline ScanResult scan_python(std::span<const std::string> roots, const WalkLimits& limits,
                                            const FsOps& fs) {
    return pkg_detail::scan_pkg(
        "python", roots, limits, fs, python_policy(), kMaxPythonMetadataBytes,
        [](const std::string& path) { return python_metadata_owner(path).has_value(); },
        [](const std::string& path, const std::optional<std::string>& bytes, Row& row) {
            auto c = python_component(path, bytes ? std::optional<std::string_view>{*bytes} : std::nullopt);
            row.name = std::move(c.name);
            row.version = std::move(c.version);
            row.version_source = std::move(c.version_source);
        });
}

/**
 * Walk `roots` for Node packages: one row per `node_modules/<pkg>/package.json` (scoped or not, at
 * any nesting the prune rule allows). kind `node`; version_source is package_json | unreadable.
 */
[[nodiscard]] inline ScanResult scan_node(std::span<const std::string> roots, const WalkLimits& limits,
                                          const FsOps& fs) {
    return pkg_detail::scan_pkg(
        "node", roots, limits, fs, node_policy(), kMaxPackageJsonBytes + 1,
        [](const std::string& path) { return node_package_from_path(path).has_value(); },
        [](const std::string& path, const std::optional<std::string>& bytes, Row& row) {
            auto c = node_component(path, bytes);
            row.name = std::move(c.name);
            row.version = std::move(c.version);
            row.version_source = std::string(to_token(c.version_source));
        });
}

/**
 * The dispatch for the two actions: scan what the OS leg offers, or nothing. Same shape and the same
 * unreadable-mount-table guard as answer_scan (nothing is walked, `make_fs` is not even called, the
 * answer is constrained with that cause). `do_scan(roots, fs)` is scan_python or scan_node.
 * `on_pruned(action, count)` is called once per walk with the directories the policy kept the walk
 * out of (pruning is the design of these actions: the plugin logs it at info level), and the count is
 * then cleared so the answer never carries `package_tree_skipped`.
 */
template <class Targets, class MakeFs, class DoScan, class OnPruned>
[[nodiscard]] inline Answer answer_pkg(std::string_view action, std::string_view os, const Targets& t,
                                       MakeFs&& make_fs, DoScan&& do_scan, OnPruned&& on_pruned) {
    ScanResult res;
    if (!t.mount_table_unreadable) {
        const FsOps fs = make_fs(t);
        res = do_scan(std::span<const std::string>{t.roots}, fs);
        on_pruned(action, res.stats.dirs_excluded);
        res.stats.dirs_excluded = 0;
    }
    return assemble_answer(action, os, t, std::move(res));
}

template <class Targets, class MakeFs, class OnPruned>
[[nodiscard]] inline Answer answer_python(std::string_view os, const Targets& t, MakeFs&& make_fs,
                                          OnPruned&& on_pruned, const WalkLimits& limits = python_limits()) {
    return answer_pkg(
        kPythonAction, os, t, make_fs,
        [&limits](std::span<const std::string> roots, const FsOps& fs) { return scan_python(roots, limits, fs); },
        on_pruned);
}

/// Node uses the scan's bounds unchanged: nesting is bounded by the prune rule, not by depth.
template <class Targets, class MakeFs, class OnPruned>
[[nodiscard]] inline Answer answer_node(std::string_view os, const Targets& t, MakeFs&& make_fs,
                                        OnPruned&& on_pruned, const WalkLimits& limits = WalkLimits{}) {
    return answer_pkg(
        kNodeAction, os, t, make_fs,
        [&limits](std::span<const std::string> roots, const FsOps& fs) { return scan_node(roots, limits, fs); },
        on_pruned);
}

} // namespace yuzu::component_inventory
