/**
 * pkg_inventory_linux_parsers.hpp — the Linux `managers` and `store_packages`
 * walks, over an INJECTED ROOT. Production passes "/"; the unit suite passes a
 * materialized tree (and, on a Linux host, drives the real entry point).
 *
 * `managers`: tool presence (dpkg, apt, rpm, dnf, pacman, apk, snap, flatpak) by
 * fstatat(AT_SYMLINK_NOFOLLOW) in /usr/bin, /usr/sbin, /bin, /sbin, plus the
 * manager-level facts a real capture supports (apt source-file count, snap file
 * count, flatpak app/runtime counts). Versions are ALWAYS `-` (ZERO
 * SUBPROCESSES). Linux never emits `unavailable`: presence is the binary, and a
 * failed fact source leaves that key out and puts its token in the status.
 *
 * `store_packages`: snaps from /var/lib/snapd/snaps/<name>_<rev>.snap, joined to
 * the mount tree (/snap/<name>/current readlink, /snap/<name>/<rev>/meta/snap.yaml
 * for version and type), and flatpak apps/runtimes from
 * /var/lib/flatpak/{app,runtime}/<id>/<arch>/<branch> (+ the `active` readlink).
 * Flatpak `metadata` is not read (no capture), so a flatpak row has no version.
 *
 * `packages`: UNSUPPORTED by design (installed_apps.list_inventory owns the Linux
 * package roster); answered before any walk.
 *
 * TWO TOKEN CLASSES. The installed-software collector fails any constrained
 * store_packages answer (a partial roster would delete server rows), so:
 *   (a) PER-ITEM FIELD DEGRADATION IS SILENT ON THE STATUS ROW and visible on
 *       the data row: the row is still emitted with version `-` / kind
 *       `unknown` / state `unknown` or `inactive`; the status stays `supported`.
 *       Covers every snap.yaml outcome (absent, EACCES, EIO, symlink, non-regular,
 *       oversized, unparseable or grammar-failing `version:`), a snap's name dir
 *       or `current` link, a flatpak branch's `active` link, and an absent or
 *       unopenable snap mount dir (every snap row `unknown`).
 *   (b) `constrained` ONLY when the LIST may be incomplete: an unopenable or
 *       unlistable snaps dir, flatpak container or nested level, entry_cap,
 *       walk_budget, row_cap, byte_cap, busy.
 * snap.yaml is snap-author-controlled, so nothing read from it can become a
 * token; it reaches a row only through the closed kind token and the snapd
 * version grammar.
 *
 * SYMLINKS ARE NEVER FOLLOWED (leaf no-follow; root-owned parents trusted): every
 * directory is opened O_NOFOLLOW, links are read with readlinkat and validated
 * as a bare component, never resolved.
 *
 * BOUNDED. A whole-action WalkBudget (entries, bytes, wall clock) sits on top of
 * the per-directory cap. The wall clock is COOPERATIVE: checked between
 * syscalls, it cannot interrupt one that blocks (an open on a stalled
 * /snap/<name>/<rev> squashfs mount). WalkSlot refuses CONCURRENT dispatches
 * (`linux:<action>:busy`) so a stall pins at most one worker per action, but the
 * sync scheduler runs its sources SEQUENTIALLY (sync_scheduler.cpp, src.collect()
 * inline), so a hung open still blocks installed_software and every later
 * daily-sync source behind it. No mountinfo/fstype guard: the roots are fixed and
 * local, and a dead FUSE daemon answers ENOTCONN rather than hanging.
 *
 * Compiled on POSIX only; the portable row/text layer is
 * pkg_inventory_parsers.hpp, the guarded primitives (`posix::`) are in
 * pkg_inventory_legs.hpp.
 */
#pragma once

#if !defined(_WIN32)

#include "pkg_inventory_legs.hpp"
#include "pkg_inventory_parsers.hpp"

#include <constraint_accumulator.hpp>
#include <posix_secure_read.hpp>
#include <wire_utf8.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::pkg_inventory::lnx {

inline constexpr std::string_view kOs = "linux";

namespace detail {

[[nodiscard]] inline std::string under(const std::filesystem::path& root, std::string_view rel) {
    std::error_code ec;
    auto base = std::filesystem::absolute(root, ec);
    if (ec) base = root;
    return (base / std::string{rel}).string();
}

/// The manager tools in Manager enum order (homebrew is the macOS leg's), the
/// logical root path reported on each row, and the probe directories searched.
struct Tool {
    Manager manager;
    std::string_view root_path; ///< "" -> written as `-`
};
inline constexpr std::array<Tool, 8> kTools{{
    {Manager::dpkg, ""},
    {Manager::apt, "/etc/apt"},
    {Manager::rpm, ""},
    {Manager::dnf, ""},
    {Manager::pacman, ""},
    {Manager::apk, ""},
    {Manager::snap, "/var/lib/snapd"},
    {Manager::flatpak, "/var/lib/flatpak"},
}};
inline constexpr std::array<std::string_view, 4> kProbeDirs{"usr/bin", "usr/sbin", "bin", "sbin"};

/// Counts the entries of <root>/<rel> that pass `name_ok` and (when `need` is
/// set) classify as that kind. Absent -> 0. A failed open, an incomplete listing,
/// a per-entry stat failure or the wall clock running out -> nullopt (a lower
/// bound is never a fact) and a token under `source`.
template <typename NameOk>
[[nodiscard]] std::optional<std::size_t>
count_entries(const std::filesystem::path& root, std::string_view rel, std::string_view source,
              std::optional<posix::EntryKind> need, NameOk name_ok, const Limits& lim,
              yuzu::shared::ConstraintAccumulator& acc, WalkBudget& budget) {
    auto opened = posix::open_dir_no_follow(under(root, rel));
    if (opened.absent) return std::size_t{0};
    if (!opened.dir.valid()) {
        acc.add_failure(make_token(kOs, source, opened.detail));
        return std::nullopt;
    }
    const auto listing = posix::list_names(opened.dir, lim.max_entries_per_dir);
    posix::note_listing(acc, kOs, source, listing);
    budget.charge(listing.names.size());
    bool ok = posix::listing_complete(listing);
    std::size_t count = 0;
    for (const auto& name : listing.names) {
        if (budget.timed_out()) {
            acc.add_failure(make_token(kOs, source, "walk_budget"));
            acc.mark_incomplete();
            return std::nullopt;
        }
        if (!name_ok(name)) continue;
        if (need) {
            const auto cls = posix::classify_entry(opened.dir, name.c_str());
            if (cls.kind == posix::EntryKind::error) {
                acc.add_failure(make_token(kOs, source, cls.detail));
                ok = false;
                continue;
            }
            if (cls.kind != *need) continue;
        }
        ++count;
    }
    if (!ok) return std::nullopt;
    return count;
}

/// Row sink shared by the snap and flatpak walks: the row cap and the output-byte
/// allowance are ACTION-wide, and once either trips nothing later slips in.
struct StoreWalk {
    const Limits& lim;
    yuzu::shared::ConstraintAccumulator& acc;
    WalkBudget& budget;
    std::vector<std::string> rows;
    bool stop = false; ///< row_cap / byte_cap / walk_budget tripped: unwind everything

    bool add(std::string row) {
        if (rows.size() >= lim.max_package_rows) {
            acc.add_failure(make_token(kOs, "store_packages", "row_cap"));
            acc.mark_incomplete();
            stop = true;
            return false;
        }
        if (!budget.charge_row(row.size() + 1)) { // + the row separator
            acc.add_failure(make_token(kOs, "store_packages", "byte_cap"));
            acc.mark_incomplete();
            stop = true;
            return false;
        }
        rows.push_back(std::move(row));
        return true;
    }
    void budget_tripped(std::string_view source) {
        acc.add_failure(make_token(kOs, source, "walk_budget"));
        acc.mark_incomplete();
        stop = true;
    }
};

/// What the mount tree says about one snap file. Every field degrades silently.
struct SnapDetail {
    StoreState state = StoreState::unknown;
    std::string version;       ///< "" -> `-`
    std::string_view kind = "unknown";
};

[[nodiscard]] inline SnapDetail snap_detail(const std::vector<posix::Dir>& mounts,
                                            const SnapFile& snap) {
    SnapDetail d;
    if (mounts.empty()) return d; // no mount tree at all: state unknown, version `-`
    // The snap lives under whichever tree holds its name dir: an ABSENT name dir moves
    // on to the next tree (a stale empty /snap beside a live /var/lib/snapd/snap must
    // not empty the catalogue); any other open failure is `unknown`, without retry.
    posix::OpenDirResult name_dir;
    for (const auto& mount : mounts) {
        name_dir = posix::open_dir_no_follow_at(mount, snap.name.c_str());
        if (name_dir.dir.valid()) break;
        if (!name_dir.absent) return d; // unknown
    }
    if (!name_dir.dir.valid()) {
        d.state = StoreState::inactive; // absent in every tree
        return d;
    }
    const auto cur = posix::read_link_name(name_dir.dir, "current", 32);
    if (cur.absent) d.state = StoreState::inactive;
    else if (cur.text && snap_revision_ok(*cur.text))
        d.state = *cur.text == snap.revision ? StoreState::active : StoreState::inactive;
    // else: any detail or an unexpected target -> unknown

    // version + type from <name>/<rev>/meta/snap.yaml, whatever the state. ANY
    // failure on this chain is a per-item state, never a constraint.
    auto rev_dir = posix::open_dir_no_follow_at(name_dir.dir, snap.revision.c_str());
    if (!rev_dir.dir.valid()) return d;
    auto meta = posix::open_dir_no_follow_at(rev_dir.dir, "meta");
    if (!meta.dir.valid()) return d;
    auto yaml = yuzu::shared::read_file_no_follow_at(meta.dir.fd(), "snap.yaml", kMaxSnapYamlBytes);
    if (!yaml.ok()) return d;
    yuzu::shared::scrub_wire_bytes(yaml.data);
    if (const auto v = snap_yaml_top_level_value(yaml.data, "version"); v && snap_version_ok(*v))
        d.version = *v;
    const auto type = snap_yaml_top_level_value(yaml.data, "type");
    d.kind = snap_kind_token(type ? std::optional<std::string_view>{*type} : std::nullopt);
    return d;
}

inline void snap_rows(const std::filesystem::path& root, StoreWalk& w) {
    constexpr std::string_view kSource = "snapd_snaps";
    auto snaps = posix::open_dir_no_follow(under(root, "var/lib/snapd/snaps"));
    if (snaps.absent) return;
    if (!snaps.dir.valid()) {
        w.acc.add_failure(make_token(kOs, kSource, snaps.detail));
        return;
    }
    const auto listing = posix::list_names(snaps.dir, w.lim.max_entries_per_dir);
    posix::note_listing(w.acc, kOs, kSource, listing);
    w.budget.charge(listing.names.size());

    std::vector<SnapFile> files;
    for (const auto& n : listing.names)
        if (auto f = parse_snap_file_name(n)) files.push_back(std::move(*f));
    std::sort(files.begin(), files.end(), [](const SnapFile& a, const SnapFile& b) {
        return a.name != b.name ? a.name < b.name : a.revision < b.revision;
    });

    // The mount trees: /snap (Debian family) and /var/lib/snapd/snap (Fedora family),
    // every one that opens, consulted in this order per snap. None opens -> every row
    // is `unknown`, silently.
    std::vector<posix::Dir> mounts;
    for (const std::string_view rel : {"snap", "var/lib/snapd/snap"}) {
        auto m = posix::open_dir_no_follow(under(root, rel));
        if (m.dir.valid()) mounts.push_back(std::move(m.dir));
    }

    for (const auto& f : files) {
        if (w.budget.timed_out()) {
            w.budget_tripped(kSource);
            return;
        }
        const auto d = snap_detail(mounts, f);
        if (!w.add(format_store_row(Store::snap, f.name, d.version, d.kind, f.revision, "", "",
                                    d.state)))
            return;
    }
}

inline void flatpak_rows(const std::filesystem::path& root, StoreWalk& w) {
    struct Container {
        std::string_view rel;
        std::string_view source;
        std::string_view kind;
    };
    static constexpr std::array<Container, 2> kContainers{{
        {"var/lib/flatpak/app", "flatpak_app", "app"},
        {"var/lib/flatpak/runtime", "flatpak_runtime", "runtime"},
    }};
    for (const auto& c : kContainers) {
        if (w.stop) return;
        auto top = posix::open_dir_no_follow(under(root, c.rel));
        if (top.absent) continue;
        if (!top.dir.valid()) {
            w.acc.add_failure(make_token(kOs, c.source, top.detail));
            continue;
        }
        // One nested level: lists `dir`, then calls `visit(name)` for
        // every real, well-named subdirectory. A failure to open or list a level
        // leaves rows under it missing, so it is a token (list incompleteness).
        auto each_child = [&](const posix::Dir& dir, auto&& visit) {
            if (w.budget.exhausted()) {
                w.budget_tripped(c.source);
                return;
            }
            const auto names = posix::list_names(dir, w.lim.max_entries_per_dir);
            posix::note_listing(w.acc, kOs, c.source, names);
            w.budget.charge(names.names.size());
            for (const auto& name : names.names) {
                if (w.stop) return;
                if (!version_dir_name_ok(name)) continue;
                const auto cls = posix::classify_entry(dir, name.c_str());
                if (cls.kind == posix::EntryKind::error) {
                    w.acc.add_failure(make_token(kOs, c.source, cls.detail));
                    continue;
                }
                if (cls.kind != posix::EntryKind::directory) continue; // e.g. `current`
                visit(name);
            }
        };
        // Opens `parent/name`; a failure other than a vanished entry leaves rows
        // under it missing, so it is a token (list incompleteness).
        auto open_child = [&](const posix::Dir& parent,
                              const std::string& name) -> std::optional<posix::Dir> {
            auto child = posix::open_dir_no_follow_at(parent, name.c_str());
            if (child.dir.valid()) return std::move(child.dir);
            if (!child.absent) w.acc.add_failure(make_token(kOs, c.source, child.detail));
            return std::nullopt;
        };
        each_child(top.dir, [&](const std::string& id) {
            auto id_dir = open_child(top.dir, id);
            if (!id_dir) return;
            each_child(*id_dir, [&](const std::string& arch) {
                auto arch_dir = open_child(*id_dir, arch);
                if (!arch_dir) return;
                each_child(*arch_dir, [&](const std::string& branch) {
                    StoreState state = StoreState::unknown;
                    std::string commit;
                    auto branch_dir = posix::open_dir_no_follow_at(*arch_dir, branch.c_str());
                    if (branch_dir.dir.valid()) {
                        const auto active = posix::read_link_name(branch_dir.dir, "active", 64);
                        if (active.absent) state = StoreState::inactive;
                        else if (active.text && is_hex64(*active.text)) {
                            state = StoreState::active;
                            commit = *active.text;
                        }
                    }
                    (void)w.add(format_store_row(Store::flatpak, id, "", c.kind, commit, arch,
                                                 branch, state));
                });
            });
        });
    }
}

} // namespace detail

/// One `manager|...` row per detected tool (banner). `token` is set (comma-joined
/// failure tokens) iff any read failed.
[[nodiscard]] inline std::vector<std::string>
linux_manager_rows_at(const std::filesystem::path& root, std::optional<std::string>& token,
                      const Limits& lim = Limits{}) {
    token.reset();
    yuzu::shared::ConstraintAccumulator acc;
    auto budget = WalkBudget::from(lim);

    // Each probe directory is opened ONCE. Absent, or a symlink (merged-usr
    // /bin -> usr/bin answers not_a_directory), is skipped silently.
    std::vector<posix::Dir> probes;
    for (const auto rel : detail::kProbeDirs) {
        auto d = posix::open_dir_no_follow(detail::under(root, rel));
        if (d.dir.valid()) {
            probes.push_back(std::move(d.dir));
        } else if (!d.absent && d.detail != "not_a_directory") {
            acc.add_failure(make_token(kOs, "tool_dir", d.detail));
        }
    }
    auto present = [&](std::string_view tool) {
        const std::string name{tool};
        const std::string source = name + "_bin";
        for (const auto& dir : probes) {
            const auto cls = posix::classify_entry(dir, name.c_str());
            if (cls.kind == posix::EntryKind::error) {
                acc.add_failure(make_token(kOs, source, cls.detail));
                continue;
            }
            if (cls.kind != posix::EntryKind::other) return true; // a symlinked tool is still a tool
        }
        return false;
    };

    std::vector<std::string> rows;
    for (const auto& tool : detail::kTools) {
        if (!present(manager_name(tool.manager))) continue;
        Facts f;
        switch (tool.manager) {
        case Manager::apt:
            if (auto n = detail::count_entries(
                    root, "etc/apt/sources.list.d", "apt_sources_d", posix::EntryKind::regular,
                    [](const std::string& s) {
                        return s.ends_with(".list") || s.ends_with(".sources");
                    },
                    lim, acc, budget))
                f.add("sources_d_files", *n);
            break;
        case Manager::snap:
            if (auto n = detail::count_entries(
                    root, "var/lib/snapd/snaps", "snapd_snaps", std::nullopt,
                    [](const std::string& s) { return parse_snap_file_name(s).has_value(); }, lim,
                    acc, budget))
                f.add("snap_files", *n);
            break;
        case Manager::flatpak: {
            const auto any = [](const std::string&) { return true; };
            if (auto n = detail::count_entries(root, "var/lib/flatpak/app", "flatpak_app",
                                               posix::EntryKind::directory, any, lim, acc, budget))
                f.add("apps", *n);
            if (auto n = detail::count_entries(root, "var/lib/flatpak/runtime", "flatpak_runtime",
                                               posix::EntryKind::directory, any, lim, acc, budget))
                f.add("runtimes", *n);
            break;
        }
        default: break;
        }
        rows.push_back(format_manager_row(tool.manager, Presence::present, "", tool.root_path,
                                          f.str(), ""));
    }
    if (acc.any_failure()) token = acc.reason();
    return rows;
}

/// One `package|<snap|flatpak>|...` row per snap file and per flatpak
/// app/runtime branch (banner: TWO TOKEN CLASSES). Snaps first (sorted by name),
/// then flatpak apps, then runtimes.
[[nodiscard]] inline std::vector<std::string>
linux_store_rows_at(const std::filesystem::path& root, std::optional<std::string>& token,
                    const Limits& lim = Limits{}) {
    token.reset();
    yuzu::shared::ConstraintAccumulator acc;
    auto budget = WalkBudget::from(lim);
    detail::StoreWalk w{lim, acc, budget, {}, false};
    detail::snap_rows(root, w);
    if (!w.stop) detail::flatpak_rows(root, w);
    if (acc.any_failure()) token = acc.reason();
    return std::move(w.rows);
}

/// The production Linux leg body over an INJECTED root: runs the action's walk and
/// hands rows + constraint to the one emission seam (emit_result). run_linux
/// (pkg_inventory_linux.cpp) calls it with "/". `packages` is answered before any
/// walk: installed_apps.list_inventory owns the Linux package roster.
inline int run_linux_at(yuzu::CommandContext& ctx, Action a, const std::filesystem::path& root) {
    std::optional<std::string> constraint;
    std::vector<std::string> rows;
    switch (a) {
    case Action::managers: rows = linux_manager_rows_at(root, constraint); break;
    case Action::store_packages: rows = linux_store_rows_at(root, constraint); break;
    case Action::packages:
        emit_unsupported(ctx, a, kTokenLinuxPackagesOwned);
        return 0;
    }
    emit_result(ctx, a, rows, constraint);
    return 0;
}

/// run_linux_at behind the single-flight slot: the shape production runs.
inline int run_linux_guarded(yuzu::CommandContext& ctx, Action a,
                             const std::filesystem::path& root) {
    const auto slot = WalkSlot::try_acquire(a);
    if (!slot) {
        emit_result(ctx, a, {}, make_token(kOs, action_name(a), "busy"));
        return 0;
    }
    return run_linux_at(ctx, a, root);
}

} // namespace yuzu::pkg_inventory::lnx

#endif // !defined(_WIN32)
