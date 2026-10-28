/**
 * runtimes_macos_parsers.hpp -- the macOS leg's walk for the runtimes plugin's `python` action, over
 * an INJECTED ROOT (production passes "/", the unit suite a materialized fixture tree).
 *
 * POSIX only. It reuses the Linux leg's hop-by-hop walk layer (runtimes_linux_parsers.hpp `lnx::walk`:
 * every component opened O_NOFOLLOW from the previous fd, bounded listing, bounded file read), never
 * the path-form opens, which follow intermediate symlinks.
 *
 * WHAT IS READ (rung 1, zero subprocess): the python.org framework only.
 *   <root>/Library/Frameworks/Python.framework/Versions/<x.y>/Resources/Info.plist
 * One row per `<x.y>` directory (`Current` and any other entry, symlinks included, are skipped
 * silently). Version = the plist's full x.y.z (python_version_from_plist), else the directory name; the
 * flavour is `cpython` when CFBundleIdentifier is `org.python.python`, else `unmodelled`; vendor = that
 * identifier verbatim. A missing, unreadable, oversized or binary plist is a per-item metadata
 * shortfall: the row still reports the directory's x.y and NO constraint token is raised.
 *
 * NOT walked: Homebrew (`/opt/homebrew`, `/usr/local/Cellar`), pyenv, conda, Xcode's Python3.framework
 * under /Library/Developer/CommandLineTools: those are other ecosystems' rows or out of the machine
 * roots. There is no network-mount guard on this leg (the framework root is a local install path).
 *
 * FAILURE NEVER READS AS ABSENT. An absent framework is silent (`supported` + zero rows); a symlink at
 * any hop to the Versions directory is `macos:runtimes:symlink_refused`; an unopenable Versions
 * directory is `macos:runtimes:permission_denied` (or the matching cause). The walk layer names its
 * causes `linux:runtimes:*`; they are forwarded here under the `macos:` prefix.
 */
#pragma once

#include "runtimes_linux_parsers.hpp"
#include "runtimes_python_parsers.hpp"

#if !defined(_WIN32)

#include <array>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::runtimes::mac {

inline constexpr std::string_view kPythonVersionsRel = "Library/Frameworks/Python.framework/Versions";
/// The only candidate: a symlink anywhere on the way is never a covered alias.
inline constexpr std::array<std::string_view, 1> kPythonMacRoots{kPythonVersionsRel};

/// Info.plist read bound (a real one is ~1 KiB).
inline constexpr std::size_t kMaxPlistBytes = 256 * 1024;

/// Re-spells the walk layer's `linux:runtimes:<cause>` tokens as `macos:runtimes:<cause>`.
inline void forward_tokens(const yuzu::shared::ConstraintAccumulator& from,
                           yuzu::shared::ConstraintAccumulator& to) {
    constexpr std::string_view from_prefix = "linux:";
    const std::string reason = from.reason();
    std::size_t pos = 0;
    while (pos < reason.size()) {
        auto comma = reason.find(',', pos);
        if (comma == std::string::npos) comma = reason.size();
        std::string_view tok{reason.data() + pos, comma - pos};
        pos = comma + 1;
        if (tok.substr(0, from_prefix.size()) == from_prefix) tok.remove_prefix(from_prefix.size());
        to.add_failure(std::string{"macos:"} + std::string{tok});
    }
}

/// python: one row per `<x.y>` directory of the python.org framework under `root`.
[[nodiscard]] inline std::vector<std::string> python_rows_at(
    const std::filesystem::path& root, yuzu::shared::ConstraintAccumulator& acc,
    const lnx::WalkConfig& cfg = {}) {
    using namespace lnx::walk;
    std::vector<std::string> rows;
    ConstraintAccumulator walk_acc; // linux:-spelled causes, forwarded as macos: on the way out
    WalkBudget budget{cfg.limits};
    const std::string logical{"/" + std::string{kPythonVersionsRel}};
    if (const DirHandle versions =
            open_path(root.string(), kPythonVersionsRel, kPythonMacRoots, cfg, walk_acc)) {
        for (const auto& e : list_entries(versions.get(), walk_acc, budget)) {
            if (e.type != EntryType::directory || !looks_like_major_minor(e.name)) continue;
            PythonRecord rec;
            rec.version = e.name;
            rec.install_path = lnx::join_logical(logical, e.name);
            // Per-item metadata: any failure below leaves the directory-name version, no token.
            Opened ver = open_child(versions.get(), e.name);
            if (ver.status == OpenStatus::opened) {
                Opened res = open_child(ver.dir.get(), "Resources");
                if (res.status == OpenStatus::opened) {
                    const auto rr = read_file_bounded_at(::dirfd(res.dir.get()), "Info.plist",
                                                         kMaxPlistBytes);
                    if (rr.status == ReadStatus::ok) {
                        if (auto v = python_version_from_plist(rr.text)) rec.version = std::move(*v);
                        const auto id = plist_string_value(rr.text, "CFBundleIdentifier");
                        if (id) {
                            rec.vendor = *id;
                            if (*id == "org.python.python") rec.flavour = PythonFlavour::cpython;
                        }
                    }
                }
            }
            if (!push_row(rows, python_row(rec), budget, walk_acc)) break;
        }
    }
    forward_tokens(walk_acc, acc);
    return rows;
}

/// The macOS leg body with the root injected: `python` is read, the dotnet/jvm actions stay planned.
inline int run_macos_at(yuzu::CommandContext& ctx, Action a, const std::filesystem::path& root) {
    if (a != Action::python) {
        emit_planned(ctx, a, "macos:planned");
        return 0;
    }
    yuzu::shared::ConstraintAccumulator acc;
    const auto rows = python_rows_at(root, acc);
    emit_read(ctx, a, rows, acc);
    return 0;
}

} // namespace yuzu::runtimes::mac

#endif // !defined(_WIN32)
