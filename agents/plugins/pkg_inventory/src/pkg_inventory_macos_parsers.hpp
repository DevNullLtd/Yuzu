/**
 * pkg_inventory_macos_parsers.hpp — the macOS Homebrew walks, over an INJECTED
 * ROOT. Production passes "/"; the unit suite passes a materialized tree.
 *
 * NOVEL DESIGN. The peripherals injected-root precedent is Linux-only
 * (peripherals_macos.cpp has no `_at` seam), so these seams have no template.
 *
 * TWO PREFIXES. Homebrew lives at /opt/homebrew on Apple silicon and at
 * /usr/local on Intel; a Mac migrated between architectures (or running both
 * under Rosetta) can have both. Every walk probes BOTH, in that order, and
 * reports each detected prefix as its own manager row (root_path names the
 * logical prefix). A package installed in both prefixes yields one row per
 * prefix, and each `packages` row names its prefix in its last field.
 *
 * WHAT COUNTS AS HOMEBREW. A prefix is Homebrew iff at least one of
 * `Library/Taps`, `Cellar`, `Caskroom` exists under it. Only a marker that
 * opened, or that failed in a way that proves something is there
 * (permission_denied, symlink_refused, not_a_directory), counts: an `io_error`
 * (EMFILE, EIO, ...) proves nothing, and neither does a failure of a prefix
 * root whose bare existence proves nothing -- /usr/local exists on every Mac,
 * whereas /opt/homebrew exists only when Homebrew does. An absent marker counts
 * 0 (taps/formulae/casks facts); an unreadable, symlinked or TRUNCATED marker is
 * a constrained token and its fact is omitted (a lower bound is never a fact,
 * never a false 0). No process is spawned (no `brew` invocation, no version
 * string is read: the manager row's version field is always "-").
 *
 * Filesystem layout read (formula and cask names/versions are directory names):
 *   <repository>/Library/Taps/<org>/<repo> -> taps
 *   <prefix>/Cellar/<formula>/<version>    -> formulae / package|...|formula
 *   <prefix>/Caskroom/<cask>/<version>     -> casks    / package|...|cask
 * Homebrew's REPOSITORY (the directory that holds Library/) is the prefix itself
 * on Apple silicon and on Intel installs that predate the move, but
 * `<prefix>/Homebrew` on current Intel installs (see Homebrew's own
 * Library/Homebrew/utils/os.sh: HOMEBREW_DEFAULT_REPOSITORY), so Taps is probed
 * at `<prefix>/Homebrew/Library/Taps` first, then `<prefix>/Library/Taps`; the
 * first that is not absent wins. Cellar and Caskroom sit at the prefix on both.
 * Entries that are not real directories (files, symlinks) and names that fail
 * version_dir_name_ok (dot-prefixed `.metadata`/`.keepme`, separators, control
 * characters) are skipped by design: Homebrew creates real directories.
 *
 * SYMLINKS ARE NEVER FOLLOWED. Every marker is reached the same way: the prefix
 * root is opened with O_NOFOLLOW (its own parents, /opt and /usr, are owned by
 * the OS), then each marker component is one openat + O_NOFOLLOW hop. A
 * symlinked prefix, Library, Taps, Cellar or Caskroom is therefore refused and
 * reported as a constraint (`not_a_directory`: the kernel answers ENOTDIR to
 * O_DIRECTORY|O_NOFOLLOW on a link; `symlink_refused` is ELOOP, a link loop in
 * the path), never read.
 *
 * BOUNDED. Each action has its own whole-ACTION budget (entries read, output
 * bytes, wall clock) on top of the per-directory cap; exhausting one is a
 * `walk_budget` / `byte_cap` constraint, never a silently shorter result. The
 * wall clock is COOPERATIVE: it is checked between syscalls and cannot interrupt
 * one that blocks (a stalled network mount inside the tree). That is contained,
 * not cured, by WalkSlot: at most one walk per action is in flight, so a stalled
 * filesystem pins at most one agent worker per action and a further dispatch
 * reports `macos:<action>:busy` instead of pinning another.
 *
 * POINT IN TIME. Names are read from a live tree: an entry removed between the
 * directory listing and its classification (a `brew upgrade` running while the
 * agent walks) is skipped as absent, not reported as a constraint.
 *
 * USER PREFIXES (`packages` only; `managers` reports machine prefixes only). After the
 * two machine prefixes the walk looks for a Homebrew a user installed in their own
 * home: `~/homebrew` and `~/.homebrew` under each real /Users home. The trust rule,
 * enforced hop by hop from OPEN DESCRIPTORS (the agent runs as root over trees any
 * local account can write, so a path is never re-resolved):
 *   - /Users is opened no-follow; each entry name must be eligible (not a dotfile) and,
 *     BEFORE any stat, not on a network mount (the run-start mount snapshot);
 *   - the home is a directory as seen without following a link, owned by uid >= the floor
 *     (500), opened no-follow, and its OWNER is re-read from the held descriptor;
 *   - each candidate is a directory without following a link (a symlink or a plain file
 *     there is "no prefix here" and skipped silently), opened no-follow from the home
 *     descriptor, and its owner (fstat of the held descriptor) must EQUAL the home's
 *     owner, else `macos:homebrew_user_prefix:owner_mismatch` and nothing under it is
 *     opened: another account cannot plant a prefix in a home it does not own;
 *   - Cellar and Caskroom are reached by openat from that verified prefix descriptor.
 * A failed read of a user-owned prefix constrains the whole `packages` answer (a named,
 * compile-time token; never a user name or a path), like every other read failure here.
 * Rows carry the home directory's NAME as owner and the literal `~/<candidate>` as
 * prefix; no absolute home path reaches a row or a token. The owner is the directory
 * name, not a directory-service lookup.
 *
 * RECEIPTS. A formula's version directory may hold INSTALL_RECEIPT.json, the installing
 * account's own record of the install time, the tap and whether the user asked for it.
 * It is opened no-follow from the version directory's descriptor and read (bounded) only
 * when it is a regular file; its values reach a row only when the file's owner equals the
 * version directory's owner. The owner rule gates PARSING and reporting: the bounded read
 * has already happened (posix_secure_read.hpp returns the owner after the bytes), and
 * a file of another account is dropped unparsed. Receipt values are the owner's own
 * claim, validated for shape (parse_brew_receipt) and never trusted; a missing,
 * unreadable, foreign or malformed receipt is `-` in the row, never a token and never a
 * failed row. Casks have no receipt and are never read.
 *
 * Compiled on POSIX only; the portable row/text layer is
 * pkg_inventory_parsers.hpp, the guarded walk primitives (`posix::`) are in
 * pkg_inventory_legs.hpp.
 */
#pragma once

#if !defined(_WIN32)

#include "pkg_inventory_legs.hpp"
#include "pkg_inventory_parsers.hpp"

#include <constraint_accumulator.hpp>
#include <macos_user_home_entry.hpp>
#include <network_fstype.hpp>
#include <posix_secure_read.hpp>
#if defined(__APPLE__)
#include <macos_network_mounts.hpp>
#endif

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <initializer_list>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::pkg_inventory::mac {

/// What the user-prefix walk needs beyond the injected root: the run-start network-mount snapshot
/// (an unreadable table is `mounts_unreadable`, never an empty guard) and the uid floor of a real
/// home (injectable so a test proves the floor without root).
struct UserPrefixConfig {
    std::vector<std::string> network_mounts;
    bool mounts_unreadable = false;
    std::uint32_t min_home_uid = yuzu::shared::kMinUserHomeUid;
};

namespace detail {

inline constexpr std::string_view kOs = "macos";

/// One Homebrew prefix. `bare_proves_homebrew`: the prefix ROOT existing (in any
/// state) is itself evidence Homebrew is installed -- true for /opt/homebrew,
/// false for /usr/local, which exists on every Mac.
struct Prefix {
    std::string_view path;
    bool bare_proves_homebrew;
};

/// Apple silicon first, then Intel. Logical (un-rooted) paths without the
/// leading slash, so `root / path` composes with any injected root.
inline constexpr std::array<Prefix, 2> kPrefixes{{{"opt/homebrew", true}, {"usr/local", false}}};

/// The two package containers under a prefix, in walk order.
struct Container {
    std::string_view rel;
    std::string_view source;      ///< token source under a machine prefix
    std::string_view user_source; ///< token source under a user-owned prefix
    PackageKind kind;
};
inline constexpr std::array<Container, 2> kContainers{{
    {"Cellar", "homebrew_cellar", "homebrew_user_cellar", PackageKind::formula},
    {"Caskroom", "homebrew_caskroom", "homebrew_user_caskroom", PackageKind::cask},
}};

/// Where Library/Taps lives: under the repository, which is `<prefix>/Homebrew`
/// on current Intel installs and the prefix itself elsewhere (banner). Probed in
/// this order.
inline constexpr std::array<std::string_view, 3> kTapsNested{"Homebrew", "Library", "Taps"};
inline constexpr std::array<std::string_view, 2> kTapsFlat{"Library", "Taps"};

[[nodiscard]] inline std::string under(const std::filesystem::path& root, std::string_view rel) {
    std::error_code ec;
    auto base = std::filesystem::absolute(root, ec);
    if (ec) base = root;
    return (base / std::string{rel}).string();
}

[[nodiscard]] inline std::string logical(std::string_view prefix) {
    return "/" + std::string{prefix};
}

/// The result of opening a marker chain, plus whether the (failed or absent)
/// hop was the prefix ROOT itself.
struct Opened {
    posix::OpenDirResult r;
    bool root_hop = false;
};

/// Opens <root>/<prefix>/<components...> one hop at a time: the prefix root with
/// an O_NOFOLLOW open, then each component with openat + O_NOFOLLOW. Opening the
/// joined string in one call would guard only its FINAL component -- the kernel
/// still resolves every intermediate one through symlink-following path
/// resolution -- so a swapped-in prefix or Library link would be read as the
/// real thing (mirrors autoruns_macos.cpp's open_dir_no_follow_at_checked chain
/// for the identical reason). The prefix root's own parents (/opt, /usr) are
/// owned by the OS, so the one-string open of it is the trusted injected root
/// plus a fixed literal. `r.absent` means some hop is ENOENT; `r.detail` names
/// any other failure (a symlink is `not_a_directory`, see the banner).
[[nodiscard]] inline Opened open_under_prefix(const std::filesystem::path& root,
                                              std::string_view prefix,
                                              std::span<const std::string_view> components) {
    Opened out;
    out.r = posix::open_dir_no_follow(under(root, prefix));
    if (!out.r.dir.valid()) {
        out.root_hop = true;
        return out;
    }
    for (const auto component : components) {
        const std::string name{component};
        out.r = posix::open_dir_no_follow_at(out.r.dir, name.c_str());
        if (!out.r.dir.valid()) return out; // absent, or a real failure: stop at this hop
    }
    return out;
}

[[nodiscard]] inline Opened open_under_prefix(const std::filesystem::path& root,
                                              std::string_view prefix,
                                              std::initializer_list<std::string_view> components) {
    return open_under_prefix(
        root, prefix, std::span<const std::string_view>{components.begin(), components.size()});
}

/// Whether this open proves Homebrew is present under `p` (banner: WHAT COUNTS AS
/// HOMEBREW): it opened; or it failed in a way that shows something is there
/// (never an `io_error`, which is EMFILE/EIO/... and proves nothing), below the
/// prefix root -- or AT the root of a prefix whose bare existence is itself proof.
[[nodiscard]] inline bool proves_presence(const Prefix& p, const Opened& o) noexcept {
    if (o.r.dir.valid()) return true;
    if (o.r.absent) return false;
    if (o.r.detail == kDetailIoError) return false;
    return !o.root_hop || p.bare_proves_homebrew;
}

/// Result of counting the real, well-named subdirectories of an open directory.
struct SubdirCount {
    std::size_t count = 0;
    /// false when the count is only a lower bound: the listing was truncated or
    /// errored, a per-entry stat failed, or the wall clock ran out (a token is
    /// already in `acc` for each).
    bool ok = true;
};

/// Counts the subdirectories of `dir` that pass version_dir_name_ok, recording
/// listing truncation and per-entry stat failures under `source`. The listing
/// is charged to `budget`; the wall clock is checked per entry, so a slow
/// filesystem cannot make one large directory outlast the budget.
[[nodiscard]] inline SubdirCount count_subdirs(const posix::Dir& dir, std::string_view source,
                                               const Limits& lim,
                                               yuzu::shared::ConstraintAccumulator& acc,
                                               WalkBudget& budget) {
    SubdirCount out;
    const auto listing = posix::list_names(dir, lim.max_entries_per_dir);
    posix::note_listing(acc, kOs, source, listing);
    if (!posix::listing_complete(listing)) out.ok = false;
    budget.charge(listing.names.size());
    for (const auto& name : listing.names) {
        if (budget.timed_out()) {
            acc.add_failure(make_token(kOs, source, "walk_budget"));
            acc.mark_incomplete();
            out.ok = false;
            break;
        }
        if (!version_dir_name_ok(name)) continue;
        const auto cls = posix::classify_entry(dir, name.c_str());
        if (cls.kind == posix::EntryKind::error) {
            acc.add_failure(make_token(kOs, source, cls.detail));
            out.ok = false;
            continue;
        }
        if (cls.kind == posix::EntryKind::directory) ++out.count;
    }
    return out;
}

/// What one prefix's markers looked like.
struct MarkerState {
    bool exists = false;   ///< a marker opened, or failed in a way that proves it is there
    bool readable = false; ///< a marker opened
};

/// Counts <prefix>/<rel> subdirectories. Absent -> count 0 (marker not
/// existing); a failed open, or a count that is only a lower bound -> nullopt
/// (and a token). `state` reports whether the marker proves Homebrew is present
/// and whether it was readable, so the caller can decide the manager row.
[[nodiscard]] inline std::optional<std::size_t>
count_marker(const std::filesystem::path& root, const Prefix& prefix, std::string_view rel,
             std::string_view source, MarkerState& state, const Limits& lim,
             yuzu::shared::ConstraintAccumulator& acc, WalkBudget& budget) {
    auto opened = open_under_prefix(root, prefix.path, {rel});
    if (opened.r.absent) return std::size_t{0};
    if (proves_presence(prefix, opened)) state.exists = true;
    if (!opened.r.detail.empty()) {
        acc.add_failure(make_token(kOs, source, opened.r.detail));
        return std::nullopt;
    }
    state.readable = true;
    const auto c = count_subdirs(opened.r.dir, source, lim, acc, budget);
    // A truncated listing or a per-entry stat failure makes the count a lower
    // bound: omit it.
    if (!c.ok) return std::nullopt;
    return c.count;
}

/// Counts Library/Taps/<org>/<repo>: the well-named directories one level down
/// inside each org directory (Library/Taps is probed at both repository
/// layouts, see kTapsNested). This is the one NESTED walk in `managers` (up to
/// max_entries_per_dir orgs x max_entries_per_dir repos), so the whole-action
/// budget is checked before every org: tripping it records `walk_budget` and
/// omits the count (a lower bound is not a fact), like a per-entry stat failure.
[[nodiscard]] inline std::optional<std::size_t>
count_taps(const std::filesystem::path& root, const Prefix& prefix, MarkerState& state,
           const Limits& lim, yuzu::shared::ConstraintAccumulator& acc, WalkBudget& budget) {
    constexpr std::string_view source = "homebrew_taps";
    auto opened = open_under_prefix(root, prefix.path, kTapsNested);
    if (opened.r.absent && !opened.root_hop) opened = open_under_prefix(root, prefix.path, kTapsFlat);
    if (opened.r.absent) return std::size_t{0};
    if (proves_presence(prefix, opened)) state.exists = true;
    if (!opened.r.detail.empty()) {
        acc.add_failure(make_token(kOs, source, opened.r.detail));
        return std::nullopt;
    }
    state.readable = true;
    const auto orgs = posix::list_names(opened.r.dir, lim.max_entries_per_dir);
    posix::note_listing(acc, kOs, source, orgs);
    budget.charge(orgs.names.size());
    std::size_t taps = 0;
    bool ok = posix::listing_complete(orgs);
    for (const auto& org : orgs.names) {
        if (!version_dir_name_ok(org)) continue;
        const auto cls = posix::classify_entry(opened.r.dir, org.c_str());
        if (cls.kind == posix::EntryKind::error) {
            acc.add_failure(make_token(kOs, source, cls.detail));
            ok = false;
            continue;
        }
        if (cls.kind != posix::EntryKind::directory) continue;
        if (budget.exhausted()) {
            acc.add_failure(make_token(kOs, source, "walk_budget"));
            acc.mark_incomplete();
            ok = false;
            break;
        }
        auto org_dir = posix::open_dir_no_follow_at(opened.r.dir, org.c_str());
        if (!org_dir.dir.valid()) {
            if (!org_dir.absent) {
                acc.add_failure(make_token(kOs, source, org_dir.detail));
                ok = false;
            }
            continue;
        }
        const auto c = count_subdirs(org_dir.dir, source, lim, acc, budget);
        taps += c.count;
        if (!c.ok) ok = false;
    }
    if (!ok) return std::nullopt;
    return taps;
}

/// Why a container walk stopped. `walk_budget` recorded its own token; `cap` is `row_cap` or
/// `byte_cap`, also recorded.
enum class WalkStop { none, walk_budget, cap };

/// What the rows of one prefix say about whose they are (see format_homebrew_package_row).
struct RowScope {
    BrewScope scope = BrewScope::machine;
    std::string_view owner{}; ///< the home directory's name on a user prefix, "" on a machine one
    std::string prefix;       ///< the logical prefix: `/opt/homebrew`, `~/homebrew`, ...
};

/// The receipt of one formula version: read only when `vdir` is a real directory whose owner is
/// known, and parsed only when the file's owner equals `expected_owner` (the version directory's
/// owner). `expected_owner` is a required parameter, so a test proves the refusal without root.
/// The owner check gates PARSING: read_file_no_follow_at has already read the bounded bytes before
/// it reports the owner (posix_secure_read.hpp), and a foreign file's bytes are dropped unparsed.
/// Every failure (symlink, FIFO, directory, oversized, unreadable, foreign) is an empty receipt.
[[nodiscard]] inline BrewReceipt read_brew_receipt(const posix::Dir& vdir,
                                                   std::uint32_t expected_owner) {
    const auto f = yuzu::shared::read_file_no_follow_at(vdir.fd(), "INSTALL_RECEIPT.json",
                                                        kMaxBrewReceiptBytes);
    if (!f.ok() || f.owner_uid != expected_owner) return {};
    return parse_brew_receipt(f.data);
}

/// The receipt of Cellar/<id>/<version> via one more no-follow openat of the version directory.
[[nodiscard]] inline BrewReceipt receipt_for_version(const posix::Dir& id_dir,
                                                     const std::string& version) {
    const auto vdir = posix::open_dir_no_follow_at(id_dir, version.c_str());
    if (!vdir.dir.valid()) return {};
    const auto owner = posix::dir_owner(vdir.dir);
    if (!owner) return {};
    return read_brew_receipt(vdir.dir, *owner);
}

/// Appends one package row per <name>/<version> directory under the OPEN container `top`
/// (Cellar or Caskroom). Stops at lim.max_package_rows (`row_cap`), at the output-byte
/// allowance (`byte_cap`) or, first, at `budget` (`walk_budget`); see WalkBudget for why the
/// per-directory cap alone does not bound the action. Exhaustion that leaves NOTHING of this
/// container unread (the last id was already walked, or only non-directory entries remained)
/// records nothing here: the caller records it iff a later container is skipped. Rows already
/// appended stay: a stop is a constraint, not a discard.
[[nodiscard]] inline WalkStop
append_package_rows_from(const posix::Dir& top, std::string_view source, PackageKind kind,
                         const RowScope& rs, const Limits& lim, std::vector<std::string>& rows,
                         yuzu::shared::ConstraintAccumulator& acc, WalkBudget& budget) {
    const auto names = posix::list_names(top, lim.max_entries_per_dir);
    posix::note_listing(acc, kOs, source, names);
    budget.charge(names.names.size());
    for (const auto& id : names.names) {
        if (!version_dir_name_ok(id)) continue;
        const auto cls = posix::classify_entry(top, id.c_str());
        if (cls.kind == posix::EntryKind::error) {
            acc.add_failure(make_token(kOs, source, cls.detail));
            continue;
        }
        if (cls.kind != posix::EntryKind::directory) continue;
        if (budget.exhausted()) {
            // Stop before starting the next id-directory's version listing.
            acc.add_failure(make_token(kOs, source, "walk_budget"));
            acc.mark_incomplete();
            return WalkStop::walk_budget;
        }
        auto id_dir = posix::open_dir_no_follow_at(top, id.c_str());
        if (!id_dir.dir.valid()) {
            if (!id_dir.absent) acc.add_failure(make_token(kOs, source, id_dir.detail));
            continue;
        }
        const auto versions = posix::list_names(id_dir.dir, lim.max_entries_per_dir);
        posix::note_listing(acc, kOs, source, versions);
        budget.charge(versions.names.size());
        for (const auto& version : versions.names) {
            if (budget.timed_out()) {
                acc.add_failure(make_token(kOs, source, "walk_budget"));
                acc.mark_incomplete();
                return WalkStop::walk_budget;
            }
            if (!version_dir_name_ok(version)) continue;
            const auto vcls = posix::classify_entry(id_dir.dir, version.c_str());
            if (vcls.kind == posix::EntryKind::error) {
                acc.add_failure(make_token(kOs, source, vcls.detail));
                continue;
            }
            if (vcls.kind != posix::EntryKind::directory) continue;
            if (rows.size() >= lim.max_package_rows) {
                acc.add_failure(make_token(kOs, source, "row_cap"));
                acc.mark_incomplete();
                return WalkStop::cap;
            }
            const BrewReceipt receipt = kind == PackageKind::formula
                                            ? receipt_for_version(id_dir.dir, version)
                                            : BrewReceipt{};
            auto row = format_homebrew_package_row(id, version, kind, receipt, rs.scope, rs.owner,
                                                   rs.prefix);
            if (!budget.charge_row(row.size() + 1)) { // + the row separator
                acc.add_failure(make_token(kOs, source, "byte_cap"));
                acc.mark_incomplete();
                return WalkStop::cap;
            }
            rows.push_back(std::move(row));
        }
    }
    return WalkStop::none;
}

/// The machine-prefix form: opens <prefix>/<rel> no-follow hop by hop, then walks it. Returns
/// true when it stopped on the budget and recorded `walk_budget` itself, so the caller does not
/// also have to.
[[nodiscard]] inline bool
append_package_rows(const std::filesystem::path& root, const Prefix& prefix, std::string_view rel,
                    std::string_view source, PackageKind kind, const Limits& lim,
                    std::vector<std::string>& rows, yuzu::shared::ConstraintAccumulator& acc,
                    WalkBudget& budget) {
    auto top = open_under_prefix(root, prefix.path, {rel});
    if (top.r.absent) return false;
    if (!top.r.detail.empty()) {
        acc.add_failure(make_token(kOs, source, top.r.detail));
        return false;
    }
    const RowScope rs{BrewScope::machine, {}, logical(prefix.path)};
    return append_package_rows_from(top.r.dir, source, kind, rs, lim, rows, acc, budget) ==
           WalkStop::walk_budget;
}

// ── user-owned prefixes ──────────────────────────────────────────────────

/// Where a user installs Homebrew in their own home, in walk order. `.homebrew` is also
/// Homebrew's own state directory; without a Cellar or Caskroom it yields nothing.
inline constexpr std::array<std::string_view, 2> kUserPrefixCandidates{"homebrew", ".homebrew"};

/// Records one failure token and marks the answer incomplete: every user-walk token does both.
inline void user_fail(yuzu::shared::ConstraintAccumulator& acc, std::string_view source,
                      std::string_view detail) {
    acc.add_failure(make_token(kOs, source, detail));
    acc.mark_incomplete();
}

/// The per-home body: walks `<home>/<candidate>/{Cellar,Caskroom}` for one OPEN home descriptor.
/// `home_uid` is the owner of that held descriptor, read by the caller (the ONE production call
/// site passes dir_owner(home)); a candidate prefix whose own owner differs is refused with
/// `owner_mismatch` and nothing under it is opened. A required parameter, so a test injects a
/// different uid and proves the denial without root. `name` is the home directory's name, used as
/// the rows' owner and for the mount guard's logical path only: it never reaches a token.
[[nodiscard]] inline WalkStop
append_home_prefix_rows(const posix::Dir& home, std::uint32_t home_uid, std::string_view name,
                        const UserPrefixConfig& ucfg, const Limits& lim,
                        std::vector<std::string>& rows, yuzu::shared::ConstraintAccumulator& acc,
                        WalkBudget& budget) {
    constexpr std::string_view kPrefixSource = "homebrew_user_prefix";
    for (const auto candidate : kUserPrefixCandidates) {
        const std::string cand{candidate};
        if (yuzu::shared::touches_network_mount("/Users/" + std::string{name} + "/" + cand,
                                  ucfg.network_mounts)) {
            user_fail(acc, kPrefixSource, "network_mount");
            continue;
        }
        const auto cls = posix::classify_entry(home, cand.c_str());
        if (cls.kind == posix::EntryKind::error) {
            user_fail(acc, kPrefixSource, cls.detail);
            continue;
        }
        if (cls.kind != posix::EntryKind::directory) continue; // none here, or a link: skipped
        auto prefix = posix::open_dir_no_follow_at(home, cand.c_str());
        if (!prefix.dir.valid()) {
            if (!prefix.absent) user_fail(acc, kPrefixSource, prefix.detail);
            continue;
        }
        const auto owner = posix::dir_owner(prefix.dir);
        if (!owner || *owner != home_uid) { // an unreadable owner compares unequal: fail closed
            user_fail(acc, kPrefixSource, "owner_mismatch");
            continue;
        }
        for (const auto& c : kContainers) {
            if (budget.exhausted()) {
                user_fail(acc, c.user_source, "walk_budget");
                return WalkStop::walk_budget;
            }
            auto top = posix::open_dir_no_follow_at(prefix.dir, std::string{c.rel}.c_str());
            if (!top.dir.valid()) {
                if (!top.absent) user_fail(acc, c.user_source, top.detail);
                continue;
            }
            if (!version_dir_name_ok(name)) { // the owner field is the name: it must be wire-safe
                user_fail(acc, kPrefixSource, "owner_name_unsupported");
                return WalkStop::none; // leave this home
            }
            const RowScope rs{BrewScope::user, name, "~/" + cand};
            const auto stop = append_package_rows_from(top.dir, c.user_source, c.kind, rs, lim,
                                                       rows, acc, budget);
            if (stop != WalkStop::none) return stop;
        }
    }
    return WalkStop::none;
}

/// After the machine prefixes: every real /Users home's own Homebrew prefixes (banner: USER
/// PREFIXES). All tokens are compile-time literals.
inline void append_user_prefix_rows(const std::filesystem::path& root, const UserPrefixConfig& ucfg,
                                    const Limits& lim, std::vector<std::string>& rows,
                                    yuzu::shared::ConstraintAccumulator& acc, WalkBudget& budget) {
    constexpr std::string_view kHomes = "user_homes";
    if (ucfg.mounts_unreadable) {
        user_fail(acc, kHomes, "mounts_unreadable"); // never opened unguarded
        return;
    }
    if (yuzu::shared::under_network_mount("/Users", ucfg.network_mounts)) {
        user_fail(acc, kHomes, "network_mount");
        return;
    }
    auto users = posix::open_dir_no_follow(under(root, "Users"));
    if (!users.dir.valid()) {
        if (!users.absent) user_fail(acc, kHomes, users.detail);
        return;
    }
    const auto listing = posix::list_names(users.dir, lim.max_entries_per_dir);
    posix::note_listing(acc, kOs, kHomes, listing);
    budget.charge(listing.names.size());
    for (const auto& name : listing.names) {
        if (budget.exhausted()) {
            user_fail(acc, kHomes, "walk_budget");
            return;
        }
        if (!yuzu::shared::home_name_eligible(name)) continue;
        if (yuzu::shared::under_network_mount("/Users/" + name, ucfg.network_mounts)) { // BEFORE any stat
            user_fail(acc, kHomes, "network_mount");
            continue;
        }
        const auto cls = posix::classify_entry(users.dir, name.c_str());
        if (cls.kind == posix::EntryKind::error) {
            user_fail(acc, kHomes, cls.detail);
            continue;
        }
        if (!yuzu::shared::is_user_home_entry(name, cls.kind == posix::EntryKind::directory,
                                              cls.uid, ucfg.min_home_uid))
            continue;
        auto home = posix::open_dir_no_follow_at(users.dir, name.c_str());
        if (!home.dir.valid()) {
            if (!home.absent) user_fail(acc, kHomes, home.detail);
            continue;
        }
        const auto home_uid = posix::dir_owner(home.dir); // the held descriptor, not the name
        if (!home_uid) {
            user_fail(acc, kHomes, kDetailIoError);
            continue;
        }
        if (*home_uid < ucfg.min_home_uid) continue;
        if (append_home_prefix_rows(home.dir, *home_uid, name, ucfg, lim, rows, acc, budget) !=
            WalkStop::none)
            return;
    }
}

} // namespace detail

/// One `manager|homebrew|...` row per Homebrew prefix detected under `root`
/// (see the header banner for the two-prefix and marker rules). Facts:
/// `taps=N;formulae=N;casks=N` (a fact is omitted when its directory could not
/// be read completely). No Homebrew anywhere -> zero rows and no constraint.
/// `token` is set (comma-joined failure tokens) iff any read failed. `lim` is the
/// resource-bound set (production: the defaults); the whole-action
/// entries/wall-clock budget covers every prefix and marker.
[[nodiscard]] inline std::vector<std::string>
macos_manager_rows_at(const std::filesystem::path& root, std::optional<std::string>& token,
                      const Limits& lim = Limits{}) {
    token.reset();
    yuzu::shared::ConstraintAccumulator acc;
    std::vector<std::string> rows;
    auto budget = WalkBudget::from(lim);
    for (const auto& prefix : detail::kPrefixes) {
        // Per-prefix accumulator: an `unavailable` row's reason must name only
        // this prefix's failures, while the status row sees every prefix's.
        yuzu::shared::ConstraintAccumulator pacc;
        detail::MarkerState state;
        const auto taps = detail::count_taps(root, prefix, state, lim, pacc, budget);
        const auto formulae = detail::count_marker(root, prefix, "Cellar", "homebrew_cellar", state,
                                                   lim, pacc, budget);
        const auto casks = detail::count_marker(root, prefix, "Caskroom", "homebrew_caskroom", state,
                                                lim, pacc, budget);
        merge_tokens(acc, pacc);
        if (!state.exists) continue; // no Homebrew marker under this prefix
        Facts f;
        if (taps) f.add("taps", *taps);
        if (formulae) f.add("formulae", *formulae);
        if (casks) f.add("casks", *casks);
        if (state.readable) {
            rows.push_back(format_manager_row(Manager::homebrew, Presence::present, "",
                                              detail::logical(prefix.path), f.str(), ""));
        } else {
            // Something is there but nothing could be read: the reason field
            // carries this prefix's tokens.
            rows.push_back(format_manager_row(Manager::homebrew, Presence::unavailable, "",
                                              detail::logical(prefix.path), "-", pacc.reason()));
        }
    }
    if (acc.any_failure()) token = acc.reason();
    return rows;
}

/// One eleven-field `package|homebrew|...` row (format_homebrew_package_row) per
/// Cellar/<formula>/<version> and Caskroom/<cask>/<version> directory, over both machine
/// prefixes and then every real user home's own prefixes (banner: USER PREFIXES), capped at
/// lim.max_package_rows (`row_cap`), at lim.max_output_bytes of emitted rows (`byte_cap`) and,
/// whole-action, at lim.max_walk_entries/max_walk_seconds (`walk_budget`). Sorted within each
/// (prefix, kind) block, so output is deterministic.
[[nodiscard]] inline std::vector<std::string>
macos_package_rows_at(const std::filesystem::path& root, std::optional<std::string>& token,
                      const Limits& lim = Limits{}, const UserPrefixConfig& ucfg = {}) {
    token.reset();
    yuzu::shared::ConstraintAccumulator acc;
    std::vector<std::string> rows;
    auto budget = WalkBudget::from(lim);
    // `walk_budget` is recorded once: by append_package_rows when it trips inside a
    // container, otherwise here, at the first container the exhausted budget makes
    // us skip (a budget that dies exactly at a container boundary, or on a listing
    // of only non-directory entries, would otherwise skip the rest silently).
    bool budget_recorded = false;
    // The byte cap has no equivalent dedup: `budget.exhausted()` above checks only
    // entries/deadline, so once bytes run out the loop still opens (and lists, and
    // discards) every remaining container, each recording its own `byte_cap` token.
    // Bounded (at most 3 more, fixed by kPrefixes x kContainers) and each token is
    // truthful for what it names, so this is wasted work, not a wrong result.
    [&] {
        for (const auto& prefix : detail::kPrefixes) {
            for (const auto& c : detail::kContainers) {
                if (budget.exhausted()) {
                    if (!budget_recorded) {
                        acc.add_failure(make_token(detail::kOs, c.source, "walk_budget"));
                        acc.mark_incomplete();
                    }
                    return;
                }
                if (detail::append_package_rows(root, prefix, c.rel, c.source, c.kind, lim, rows,
                                                acc, budget))
                    budget_recorded = true;
            }
        }
        detail::append_user_prefix_rows(root, ucfg, lim, rows, acc, budget);
    }();
    if (acc.any_failure()) token = acc.reason();
    return rows;
}

#if defined(__APPLE__)
/// The production user-prefix config: the network mounts from the kernel's mount table, read once
/// at dispatch start. An unreadable table is `mounts_unreadable` (the user walk is skipped with a
/// token), never an empty guard. The reader is a parameter (the live getmntinfo_r_np snapshot by
/// default) so a test can feed a failed one.
[[nodiscard]] inline UserPrefixConfig production_user_prefix_config(
    std::optional<std::vector<std::string>> (*read_mounts)() =
        &yuzu::shared::read_macos_network_mounts) {
    UserPrefixConfig cfg;
    auto mounts = read_mounts();
    cfg.mounts_unreadable = !mounts;
    if (mounts) cfg.network_mounts = std::move(*mounts);
    return cfg;
}
#endif

/// The production macOS leg body over an INJECTED root: runs the action's walk
/// and hands rows + constraint to the one emission seam (emit_result), so the
/// wire status row and the CC-07 typed status are produced here. run_macos
/// (pkg_inventory_macos.cpp) calls it with "/"; the unit suite drives it over a
/// fixture tree through a real CommandContext. MUTATION: passing std::nullopt
/// instead of `constraint` below fails the forced-constraint seam case in
/// test_pkg_inventory_macos_parsers.cpp.
inline int run_macos_at(yuzu::CommandContext& ctx, Action a, const std::filesystem::path& root,
                        const UserPrefixConfig& ucfg = {}) {
    std::optional<std::string> constraint;
    std::vector<std::string> rows;
    switch (a) {
    case Action::managers: rows = macos_manager_rows_at(root, constraint); break;
    case Action::packages: rows = macos_package_rows_at(root, constraint, Limits{}, ucfg); break;
    case Action::store_packages:
        // Reads nothing: installed_apps owns the macOS application list.
        emit_unsupported(ctx, a, kTokenMacosStoreOwned);
        return 0;
    }
    emit_result(ctx, a, rows, constraint);
    return 0;
}

/// run_macos_at behind the single-flight slot: the shape production runs.
inline int run_macos_guarded(yuzu::CommandContext& ctx, Action a,
                             const std::filesystem::path& root,
                             const UserPrefixConfig& ucfg = {}) {
    // `store_packages` is unsupported by design and walks nothing: answer it without the slot
    // so an overlapping dispatch is never told `busy` for an action that cannot be in flight.
    if (a == Action::store_packages) return run_macos_at(ctx, a, root, ucfg);
    const auto slot = WalkSlot::try_acquire(a);
    if (!slot) {
        emit_result(ctx, a, {}, make_token(detail::kOs, action_name(a), "busy"));
        return 0;
    }
    return run_macos_at(ctx, a, root, ucfg);
}

} // namespace yuzu::pkg_inventory::mac

#endif // !defined(_WIN32)
