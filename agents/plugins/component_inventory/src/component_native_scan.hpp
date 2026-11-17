/**
 * component_native_scan.hpp -- the `native` action of the component_inventory plugin: versioned shared
 * libraries (ELF .so on Linux, Mach-O .dylib on macOS) shipped inside applications.
 *
 * Portable: no OS header. Like scan() it goes through the FsOps seam, so the unit test drives it over
 * an in-memory tree and a fake clock; the readers themselves are component_native_parsers.hpp.
 *
 * SAME DISCIPLINE AS scan() (component_scan.hpp): one deadline computed once and checked between
 * files and once more at the end; one open per candidate, every byte read through that FileView;
 * the same completeness rule (nothing that hides rows reads as complete). What differs:
 *  - the candidate predicate is the leaf name of a shared library (WalkPolicy::is_candidate);
 *  - the section cap is 5,000 rows (native_limits()), every other bound is the scan's;
 *  - a file whose name matches but whose magic does not is not a library and gives no row; a file
 *    with the right magic that cannot be parsed inside its bounds gives a row with what the file name
 *    offers (version_source `unreadable` unless the name carries a version) and the scan stays
 *    complete: an item-level gap, nothing hidden;
 *  - a file the walk listed that cannot be opened (a link or non-regular file it was swapped for,
 *    refused, or gone) is a file that changed under the scan: Stop::archive_changed, no row;
 *  - package-owned trees (WalkPolicy::skip_dir) are counted and reported on the status row by the
 *    informational token `package_tree_skipped`, never a silent skip (ADR-0028 Decision 4).
 * The one deadline does not interrupt a read in flight; the leg's banner (component_fs_posix.cpp)
 * states that residual.
 *
 * Untrusted bytes (a SONAME, an install name, a path) reach a row only through wire_field, in
 * format_component_row; the name rules additionally map any non-printable byte to '?'.
 */
#pragma once

#include "component_native_parsers.hpp"
#include "component_scan.hpp"
#include "component_walk.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace yuzu::component_inventory {

inline constexpr std::string_view kNativeAction = "native";

/// The native action's bounds: the scan's, with a 5,000-row section cap.
[[nodiscard]] inline WalkLimits native_limits() {
    WalkLimits l;
    l.max_rows = 5000;
    return l;
}

/// Describes the file named `leaf` of `size` bytes read through `rd`, or says it is not a shared
/// library (nullopt: no row). describe_linux_file / describe_macos_file are the two real ones.
using NativeParse =
    std::function<std::optional<NativeDescription>(std::string_view leaf, const ReadAt& rd, std::uint64_t size)>;

/**
 * Walk `roots` under `policy`, then read every candidate library through `parse`.
 */
[[nodiscard]] inline ScanResult scan_native(std::span<const std::string> roots, const WalkLimits& limits,
                                            const FsOps& fs, const WalkPolicy& policy, const NativeParse& parse) {
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

    // One row per candidate at most, and the walk already holds its candidates to the section and
    // per-anchor caps: neither can be exceeded here, so this loop keeps no quota of its own.
    for (const auto& c : walked.candidates) {
        if (fs.now() >= deadline) {
            record(Stop::budget_time);
            break;
        }
        const std::string_view leaf = scan_detail::leaf_of(c.path);

        Row row;
        row.kind = "native";
        row.path = c.path;
        row.anchor_app = c.anchor_app;

        std::optional<NativeDescription> desc;
        if (const auto fv = fs.open_file(c.path)) {
            row.size = fv->size;
            row.mtime = fv->mtime;
            desc = parse(leaf, fv->read_at, fv->size);
            if (!fv->unchanged())
                record(Stop::archive_changed);
        } else {
            record(Stop::archive_changed); // listed, then not openable: it changed under the scan
            continue;
        }
        if (!desc)
            continue; // the name matched, the magic did not: not a library

        row.name = std::move(desc->name);
        row.version = std::move(desc->version);
        row.version_source = std::string(to_token(desc->version_source));

        if (desc->version_source == NativeVersionSource::unreadable)
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

/**
 * The `native` answer: scan what the OS leg offers, or nothing. Same shape and the same
 * unreadable-mount-table guard as answer_scan; the status row names `native`.
 */
template <class Targets, class MakeFs>
[[nodiscard]] inline Answer answer_native(std::string_view os, const Targets& t, MakeFs&& make_fs,
                                          const WalkLimits& limits, const WalkPolicy& policy,
                                          const NativeParse& parse) {
    ScanResult res;
    if (!t.mount_table_unreadable) {
        const FsOps fs = make_fs(t);
        res = scan_native(t.roots, limits, fs, policy, parse);
    }
    return assemble_answer(kNativeAction, os, t, std::move(res));
}

} // namespace yuzu::component_inventory
