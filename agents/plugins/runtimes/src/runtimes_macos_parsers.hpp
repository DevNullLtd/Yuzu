/**
 * runtimes_macos_parsers.hpp -- the macOS leg's walks for the runtimes plugin's `python`, `dotnet`
 * and `jvm` actions, over an INJECTED ROOT (production passes "/", the unit suite a materialized
 * fixture tree).
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
 * roots.
 *
 * dotnet (rung 1, zero subprocess, never `dotnet --list-runtimes`): the Microsoft installer's machine
 * root, directory NAMES only, hop-by-hop on the Linux leg's walk layer:
 *   <root>/usr/local/share/dotnet/{shared/<framework>/<version>, sdk/<version>}
 *   <root>/usr/local/share/dotnet/x64/{shared/..., sdk/...}   (the Rosetta install on Apple silicon)
 * The x64 sub-root's rows carry vendor `Microsoft` and its own install path; the native root's rows
 * carry no vendor (`-`), as on Linux. Rows are sorted and deduplicated. Unlike the Linux leg, a
 * framework / version / sdk entry that is itself a SYMLINK is `symlink_refused` (constrained), not a
 * silent alias: no macOS installer lays down alias entries there, so a symlink is unexplained.
 * NOT walked: Homebrew's dotnet (`/opt/homebrew/opt/dotnet`), dotnet-install.sh under $HOME.
 *
 * jvm (rung 1): one row per directory under <root>/Library/Java/JavaVirtualMachines.
 *   <entry>/Contents/Home/release   the JDK `release` file (parse_release_file): version, flavour
 *                                   (IMAGE_TYPE) and vendor (IMPLEMENTOR); the install path is the
 *                                   bundle `/Library/Java/JavaVirtualMachines/<entry>`.
 *   <entry>/Contents/Info.plist     only when `release` is ABSENT: the JavaVM dictionary's
 *                                   JVMVersion / JVMVendor (flavour unmodelled).
 * With neither, the bundle is still a row (flavour unmodelled, version and vendor `-`) plus
 * `release_missing`. A `Contents/Home` symlink is `symlink_refused` (the plist is still tried). An
 * ENTRY that is a symlink (`brew link`ed openjdk.jdk, a vendor alias) is skipped silently and never
 * followed: Homebrew / sdkman / jenv installs are other ecosystems' roots and are not inventoried.
 * No JDK is installed on the development Mac, so this leg is verified against fixture trees built from
 * the documented bundle layout, not a real capture.
 *
 * NETWORK MOUNTS ARE NOT WALKED, as on the Linux leg: production passes `production_config()`, whose
 * `network_mounts` is the getmntinfo_r_np(MNT_NOWAIT) snapshot (agents/shared/macos_network_mounts.hpp,
 * unprivileged, answered from the kernel's cache). A Versions root that is on, under or contains a
 * network mount (a mount-on `/Library`, `/Library/Frameworks/...`, or anything beneath the Versions
 * directory) is skipped before any syscall touches it and records `macos:runtimes:network_fs_skipped`.
 * When the table cannot be read the walk runs guarded only by that read and records
 * `macos:runtimes:mountinfo_unreadable` (the token keeps the Linux leg's name). Residuals a plugin
 * cannot close: a mount that appears after the snapshot, a stacked filesystem over a dead network
 * mount, and a network type the deny-list does not name.
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

#if defined(__APPLE__)
#include <macos_network_mounts.hpp> // yuzu::shared::read_macos_network_mounts (agents/shared)
#endif

#include <algorithm>
#include <array>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::runtimes::mac {

inline constexpr std::string_view kPythonVersionsRel = "Library/Frameworks/Python.framework/Versions";
/// The only candidate: a symlink anywhere on the way is never a covered alias.
inline constexpr std::array<std::string_view, 1> kPythonMacRoots{kPythonVersionsRel};

/// Info.plist read bound (a real one is ~1 KiB).
inline constexpr std::size_t kMaxPlistBytes = 256 * 1024;

/// The mount snapshot could not be read (the walk then runs guarded only by what it did read).
inline constexpr std::string_view kTokMountsUnreadable = "macos:runtimes:mountinfo_unreadable";

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

inline constexpr std::string_view kDotnetRel = "usr/local/share/dotnet";
inline constexpr std::string_view kDotnetX64Rel = "usr/local/share/dotnet/x64";
/// Candidate set for the alias rule (a symlinked `x64` naming the parent is a covered alias; any
/// other symlink on the way is refused).
inline constexpr std::array<std::string_view, 2> kDotnetMacRoots{kDotnetRel, kDotnetX64Rel};
inline constexpr std::string_view kJvmRel = "Library/Java/JavaVirtualMachines";
inline constexpr std::array<std::string_view, 1> kJvmMacRoots{kJvmRel};

namespace detail {

/// The Linux dotnet loop body (runtimes_linux_parsers.hpp `dotnet_rows_at`), lifted for one open
/// dotnet root, with two macOS differences: `vendor` is stamped on every row, and an entry that is a
/// symlink is refused visibly instead of skipped as an alias.
inline void dotnet_walk_root(DIR* dotnet, const std::string& logical, std::string_view vendor,
                             std::vector<std::string>& rows, lnx::walk::WalkBudget& budget,
                             yuzu::shared::ConstraintAccumulator& acc) {
    using namespace lnx::walk;
    const auto row_for = [&](std::string_view fw, std::string_view ver, std::string path)
        -> std::optional<std::string> {
        const auto e = dotnet_entry_from_dir(fw, ver);
        if (!e) return std::nullopt;
        return format_runtime_row("dotnet", flavour_token(e->flavour), e->version, path, vendor);
    };
    if (const DirHandle shared =
            take_or_record(open_child(dotnet, "shared"), acc, /*refuse_alias=*/true)) {
        for (const auto& fw : list_entries(shared.get(), acc, budget)) {
            if (budget.exhausted) break;
            if (fw.type == EntryType::symlink) {
                acc.add_failure(lnx::kTokSymlinkRefused);
                continue;
            }
            if (fw.type != EntryType::directory) continue;
            const DirHandle fwh =
                take_or_record(open_child(shared.get(), fw.name), acc, /*refuse_alias=*/true);
            if (!fwh) continue;
            for (const auto& ver : list_entries(fwh.get(), acc, budget)) {
                if (ver.type == EntryType::symlink) {
                    if (dotnet_entry_from_dir(fw.name, ver.name)) acc.add_failure(lnx::kTokSymlinkRefused);
                    continue;
                }
                if (ver.type != EntryType::directory) continue;
                auto row = row_for(fw.name, ver.name,
                                   lnx::join_logical(lnx::join_logical(logical + "/shared", fw.name),
                                                     ver.name));
                if (row && !push_row(rows, std::move(*row), budget, acc)) break;
            }
        }
    }
    if (budget.exhausted) return;
    if (const DirHandle sdk =
            take_or_record(open_child(dotnet, "sdk"), acc, /*refuse_alias=*/true)) {
        for (const auto& ver : list_entries(sdk.get(), acc, budget)) {
            if (ver.type == EntryType::symlink) {
                if (dotnet_entry_from_dir("sdk", ver.name)) acc.add_failure(lnx::kTokSymlinkRefused);
                continue;
            }
            if (ver.type != EntryType::directory) continue;
            auto row = row_for("sdk", ver.name, lnx::join_logical(logical + "/sdk", ver.name));
            if (row && !push_row(rows, std::move(*row), budget, acc)) break;
        }
    }
}

/// A plist value kept only when short enough to be a vendor / version token (the walk layer's
/// per-value bound for `release` values); an over-long one is dropped and flagged by the caller.
[[nodiscard]] inline std::optional<std::string> bounded_plist_value(std::string_view xml,
                                                                    std::string_view key,
                                                                    bool& oversized) {
    auto v = plist_string_value(xml, key);
    if (v && v->size() > kMaxReleaseValueBytes) {
        oversized = true;
        return std::nullopt;
    }
    return v;
}

} // namespace detail

/// dotnet: the shared/<framework>/<version> and sdk/<version> directory names under
/// <root>/usr/local/share/dotnet and its `x64` Rosetta sub-root. Rows sorted and deduplicated.
[[nodiscard]] inline std::vector<std::string> dotnet_rows_at(
    const std::filesystem::path& root, yuzu::shared::ConstraintAccumulator& acc,
    const lnx::WalkConfig& cfg = {}) {
    using namespace lnx::walk;
    std::vector<std::string> rows;
    ConstraintAccumulator walk_acc;
    WalkBudget budget{cfg.limits};
    const std::string root_s = root.string();
    for (const std::string_view rel : kDotnetMacRoots) {
        if (budget.exhausted) break;
        const DirHandle dotnet = open_path(root_s, rel, kDotnetMacRoots, cfg, walk_acc);
        if (!dotnet) continue;
        detail::dotnet_walk_root(dotnet.get(), "/" + std::string{rel},
                                 rel == kDotnetX64Rel ? "Microsoft" : "", rows, budget, walk_acc);
    }
    std::sort(rows.begin(), rows.end());
    rows.erase(std::unique(rows.begin(), rows.end()), rows.end());
    forward_tokens(walk_acc, acc);
    return rows;
}

/// jvm: one row per bundle under <root>/Library/Java/JavaVirtualMachines (see the file comment).
[[nodiscard]] inline std::vector<std::string> jvm_rows_at(
    const std::filesystem::path& root, yuzu::shared::ConstraintAccumulator& acc,
    const lnx::WalkConfig& cfg = {}) {
    using namespace lnx::walk;
    std::vector<std::string> rows;
    ConstraintAccumulator walk_acc;
    WalkBudget budget{cfg.limits};
    const std::string logical_root{"/" + std::string{kJvmRel}};
    if (const DirHandle jvms = open_path(root.string(), kJvmRel, kJvmMacRoots, cfg, walk_acc)) {
        for (const auto& bundle : list_entries(jvms.get(), walk_acc, budget)) {
            if (bundle.type != EntryType::directory) continue; // includes symlinked entries (see above)
            const DirHandle bh = take_or_record(open_child(jvms.get(), bundle.name), walk_acc);
            if (!bh) continue;
            const std::string path = lnx::join_logical(logical_root, bundle.name);
            Opened copen = open_child(bh.get(), "Contents");
            if (copen.status == OpenStatus::failed) {
                walk_acc.add_failure(copen.token); // unreadable bundle: no row, never an empty success
                continue;
            }
            // A failure already recorded explains a missing `release` (no extra release_missing).
            bool cause_recorded = copen.status == OpenStatus::alias;
            const DirHandle contents = take_or_record(std::move(copen), walk_acc, /*refuse_alias=*/true);
            // 1. Contents/Home/release
            if (contents) {
                Opened home = open_child(contents.get(), "Home");
                cause_recorded = home.status == OpenStatus::failed || home.status == OpenStatus::alias;
                if (const DirHandle hh = take_or_record(std::move(home), walk_acc, /*refuse_alias=*/true)) {
                    const auto rr = read_file_bounded_at(::dirfd(hh.get()), "release", lnx::kMaxReleaseBytes);
                    if (rr.status == ReadStatus::failed) {
                        walk_acc.add_failure(rr.token);
                        continue;
                    }
                    if (rr.status == ReadStatus::ok) {
                        const auto fields = parse_release_file(rr.text);
                        if (fields.oversized) walk_acc.add_failure(lnx::kTokFieldOversized);
                        auto row = jvm_row(fields, path);
                        if (!row) {
                            walk_acc.add_failure(lnx::kTokReleaseUnparsable);
                            continue;
                        }
                        if (!push_row(rows, std::move(*row), budget, walk_acc)) break;
                        continue;
                    }
                }
            }
            // 2. release absent: Contents/Info.plist JavaVM JVMVersion / JVMVendor
            std::string version, vendor;
            if (contents) {
                const auto pr = read_file_bounded_at(::dirfd(contents.get()), "Info.plist", kMaxPlistBytes);
                if (pr.status == ReadStatus::failed) {
                    walk_acc.add_failure(pr.token);
                    continue;
                }
                if (pr.status == ReadStatus::ok) {
                    bool oversized = false;
                    version = detail::bounded_plist_value(pr.text, "JVMVersion", oversized).value_or("");
                    vendor = detail::bounded_plist_value(pr.text, "JVMVendor", oversized).value_or("");
                    if (oversized) walk_acc.add_failure(lnx::kTokFieldOversized);
                }
            }
            // 3. no version from either source: still a row, honestly flagged
            if (version.empty() && !cause_recorded) walk_acc.add_failure(lnx::kTokReleaseMissing);
            if (!push_row(rows,
                          format_runtime_row("jvm", flavour_token(JvmFlavour::unmodelled), version, path,
                                             vendor),
                          budget, walk_acc))
                break;
        }
    }
    forward_tokens(walk_acc, acc);
    return rows;
}

#if defined(__APPLE__)
/// The default walk bounds plus the network mounts from the kernel's mount table, read once at
/// dispatch start. An unreadable table is `mountinfo_unreadable`, not an empty guard. The reader
/// is a parameter (the live getmntinfo_r_np snapshot by default) so a test can feed a failed one.
[[nodiscard]] inline lnx::WalkConfig production_config(
    std::optional<std::vector<std::string>> (*read_mounts)() =
        &yuzu::shared::read_macos_network_mounts) {
    lnx::WalkConfig cfg;
    auto mounts = read_mounts();
    cfg.mountinfo_unreadable = !mounts;
    if (mounts) cfg.network_mounts = std::move(*mounts);
    return cfg;
}
#endif

/// The rows for action `a` under `root`, failures recorded in `acc`. An action with no arm (a future
/// one) is a visible failure, never `supported` + zero rows.
[[nodiscard]] inline std::vector<std::string> action_rows_at(
    Action a, const std::filesystem::path& root, yuzu::shared::ConstraintAccumulator& acc,
    const lnx::WalkConfig& cfg = {}) {
    switch (a) { // qualified calls: ADL on WalkConfig also finds lnx::
    case Action::dotnet: return mac::dotnet_rows_at(root, acc, cfg);
    case Action::jvm:    return mac::jvm_rows_at(root, acc, cfg);
    case Action::python: return mac::python_rows_at(root, acc, cfg);
    }
    acc.add_failure("internal_error");
    return {};
}

/// The macOS leg body with the root and walk configuration injected: all three actions are read.
/// runtimes_macos.cpp passes "/" and `production_config()`; the default `cfg` (no mounts, table
/// readable) is for the seam tests over a fixture tree.
inline int run_macos_at(yuzu::CommandContext& ctx, Action a, const std::filesystem::path& root,
                        const lnx::WalkConfig& cfg = {}) {
    yuzu::shared::ConstraintAccumulator acc;
    if (cfg.mountinfo_unreadable) acc.add_failure(kTokMountsUnreadable);
    const auto rows = mac::action_rows_at(a, root, acc, cfg);
    emit_read(ctx, a, rows, acc);
    return 0;
}

} // namespace yuzu::runtimes::mac

#endif // !defined(_WIN32)
