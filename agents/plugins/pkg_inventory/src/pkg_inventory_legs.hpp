/**
 * pkg_inventory_legs.hpp — shared seam between the pkg_inventory plugin TU and
 * its three per-OS leg TUs.
 *
 * Holds the `Action` enum and its string conversions, the per-OS entry-point
 * declarations, and the ONE result-emission helper every leg calls (status row
 * first, then data rows, then the CC-07 typed status), and the exception
 * firewall (run_guarded) that wraps the whole of execute(). Modelled on
 * peripherals_legs.hpp.
 *
 * Also holds the guarded POSIX directory primitives (`posix::`, bottom of the
 * file) the macOS walk shell uses. They are excluded on Windows, so the pure
 * text/row layer (pkg_inventory_parsers.hpp) stays free of POSIX headers.
 */
#pragma once

#include "pkg_inventory_parsers.hpp"

#include <yuzu/plugin.hpp>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#if !defined(_WIN32)
#include <yuzu/agent/scoped_fd.hpp>

#include <dirent.h>
#include <fcntl.h>
#include <posix_dir_walk.hpp>
#include <sys/stat.h>
#endif

namespace yuzu::pkg_inventory {

/// One value per `actions()` entry (pkg_inventory_plugin.cpp).
enum class Action { managers, packages };

[[nodiscard]] constexpr std::string_view action_name(Action a) noexcept {
    switch (a) {
    case Action::managers: return "managers";
    case Action::packages: return "packages";
    }
    return "managers";
}

/// nullopt for anything else, so the dispatcher can tell "unknown action" from
/// a real one.
[[nodiscard]] constexpr std::optional<Action> parse_action(std::string_view action) noexcept {
    if (action == "managers") return Action::managers;
    if (action == "packages") return Action::packages;
    return std::nullopt;
}

// ── per-OS entry points (defined by the leg TUs) ─────────────────────────
//
// Each is a READ and returns 0 unconditionally: a degraded read is not a
// failed command, and the degradation is reported through the status row and
// set_result_status. Declared unconditionally; only the DEFINITION is
// self-gated (each leg .cpp wraps its body in `#if defined(<os>)`), and the
// plugin TU calls only the host leg, so a single-OS build never needs the
// other two symbols to link.

int run_windows(yuzu::CommandContext& ctx, Action a);
int run_linux(yuzu::CommandContext& ctx, Action a);
int run_macos(yuzu::CommandContext& ctx, Action a);

// ── result emission ──────────────────────────────────────────────────────

/// Writes `status|...` FIRST, then every data row, then the CC-07 status. A
/// set `constraint` (comma-joined tokens from the walk) means at least one
/// acquisition step failed: status row `constrained` + CONSTRAINED/PARTIAL. No
/// constraint (including "manager/prefix absent, zero rows") is
/// `supported` + OK/FULL.
inline void emit_result(yuzu::CommandContext& ctx, Action a,
                        const std::vector<std::string>& data_rows,
                        const std::optional<std::string>& constraint) {
    const bool constrained = constraint.has_value();
    ctx.write_output(format_status_row(
        action_name(a), constrained ? StatusLevel::constrained : StatusLevel::supported,
        constrained ? std::string_view{*constraint} : std::string_view{}));
    for (const auto& row : data_rows)
        ctx.write_output(row);
    if (constrained)
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              *constraint);
    else
        ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
}

/// The by-design unsupported and planned outcomes (Linux `packages`, the planned
/// Linux `managers` leg, both Windows legs): `status|<action>|unsupported|<token>`
/// and no data rows.
inline void emit_unsupported(yuzu::CommandContext& ctx, Action a, std::string_view token) {
    ctx.write_output(unsupported_status_row(action_name(a), token));
    ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL, token);
}

// ── exception firewall ───────────────────────────────────────────────────

/// What `execute()` reports when something below it throws: a `constrained`
/// status row carrying the fixed provenance token (never the exception's own
/// text, which could embed a path or other untrusted-walk-observed content), the
/// typed UNAVAILABLE/PARTIAL status (the autoruns firewall's pairing) and rc 1.
/// It runs because something already threw, so it must not throw itself: a
/// failure to report is swallowed and the command still fails with rc 1.
inline int report_execute_exception(yuzu::CommandContext& ctx, std::string_view action) noexcept {
    try {
        ctx.write_output(format_status_row(action, StatusLevel::constrained, kTokenException));
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              kTokenException);
    } catch (...) {
    }
    return 1;
}

/// Runs `body` (the WHOLE of execute(), the unknown-action diagnostic included)
/// so that nothing it throws can cross the frozen plugin ABI seam unannotated.
template <typename Body>
int run_guarded(yuzu::CommandContext& ctx, std::string_view action, Body&& body) noexcept {
    try {
        return body();
    } catch (...) {
        return report_execute_exception(ctx, action);
    }
}

// ── POSIX directory primitives (thin shell; not compiled on Windows) ─────
//
// Used by the macOS walk shell (pkg_inventory_macos_parsers.hpp). Nothing
// here spawns a process: every read is open/openat/fstatat/readdir with
// O_NOFOLLOW on the leaf, so a swapped-in symlink is refused rather than
// followed (a private copy of the autoruns_macos.cpp dir_open_outcome_from_fd
// / open_dir_no_follow_checked shape; posix_dir_walk.hpp deliberately leaves
// opening to each caller). Guarded because posix_dir_walk.hpp does not exist on
// Windows; the portable row/text layer is pkg_inventory_parsers.hpp.
#if !defined(_WIN32)

namespace posix {

/// Move-only owner of a DIR*.
class Dir {
public:
    Dir() noexcept = default;
    explicit Dir(DIR* d) noexcept : d_(d) {}
    ~Dir() {
        if (d_ != nullptr) ::closedir(d_);
    }
    Dir(const Dir&) = delete;
    Dir& operator=(const Dir&) = delete;
    Dir(Dir&& o) noexcept : d_(o.d_) { o.d_ = nullptr; }
    Dir& operator=(Dir&& o) noexcept {
        if (this != &o) {
            if (d_ != nullptr) ::closedir(d_);
            d_ = o.d_;
            o.d_ = nullptr;
        }
        return *this;
    }
    [[nodiscard]] DIR* get() const noexcept { return d_; }
    [[nodiscard]] bool valid() const noexcept { return d_ != nullptr; }
    [[nodiscard]] int fd() const noexcept { return d_ != nullptr ? ::dirfd(d_) : -1; }

private:
    DIR* d_ = nullptr;
};

/// Outcome of an O_NOFOLLOW directory open. Exactly one of: opened (`dir`
/// valid), `absent` (ENOENT -- not this shell's error to report), or a real
/// constraint (`detail` non-empty).
struct OpenDirResult {
    Dir dir;
    bool absent = false;
    std::string_view detail{};
};

/// `raw_fd` is the result of an open/openat (errno still current when < 0).
/// A ScopedFd owns the descriptor until fdopendir() takes it over.
[[nodiscard]] inline OpenDirResult finish_dir_open(int raw_fd) {
    OpenDirResult r;
    if (raw_fd < 0) {
        const int err = errno;
        if (is_benign_absent_errno(err)) r.absent = true;
        else r.detail = open_failure_token(err);
        return r;
    }
    yuzu::agent::ScopedFd fd{raw_fd};
    DIR* d = ::fdopendir(fd.get());
    if (d == nullptr) {
        const int err = errno; // read before ScopedFd's close can disturb it
        if (is_benign_absent_errno(err)) r.absent = true;
        else r.detail = open_failure_token(err);
        return r;
    }
    (void)fd.release(); // fdopendir() succeeded: the DIR* owns the fd now
    r.dir = Dir{d};
    return r;
}

[[nodiscard]] inline OpenDirResult open_dir_no_follow(const std::string& path) {
    return finish_dir_open(::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
}

[[nodiscard]] inline OpenDirResult open_dir_no_follow_at(const Dir& parent, const char* name) {
    return finish_dir_open(
        ::openat(parent.fd(), name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
}

/// Lists the entry names of an open directory (sorted, so output is
/// deterministic whatever readdir order the filesystem gives), capped at
/// `max_entries` (production: kMaxEntriesPerDir). `walk` reports truncation / a
/// mid-scan readdir error.
struct DirListing {
    std::vector<std::string> names;
    yuzu::shared::DirWalkResult walk;
};

[[nodiscard]] inline DirListing list_names(const Dir& dir, std::size_t max_entries) {
    DirListing out;
    out.walk = yuzu::shared::walk_dir_capped(dir.get(), max_entries,
                                             [&](const struct dirent* entry) {
                                                 out.names.emplace_back(entry->d_name);
                                                 return true;
                                             });
    std::sort(out.names.begin(), out.names.end());
    return out;
}

enum class EntryKind { directory, regular, symlink, other, error };

/// Classifies `name` inside `parent` without following a symlink: a real
/// directory, a regular file, a symlink (target not resolved), anything else
/// (fifo, socket, device, or a vanished entry -- ENOENT race) as `other`, and a
/// failed fstatat as `error` (with `detail` set). The Homebrew walks accept
/// only `directory`; the other kinds are still named (not folded into `other`)
/// so a caller can tell a file from a link.
struct EntryClass {
    EntryKind kind = EntryKind::other;
    std::string_view detail{};
};

[[nodiscard]] inline EntryClass classify_entry(const Dir& parent, const char* name) {
    struct stat st{};
    if (::fstatat(parent.fd(), name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
        const int err = errno;
        if (is_benign_absent_errno(err)) return {EntryKind::other, {}};
        return {EntryKind::error, open_failure_token(err)};
    }
    if (S_ISDIR(st.st_mode)) return {EntryKind::directory, {}};
    if (S_ISREG(st.st_mode)) return {EntryKind::regular, {}};
    if (S_ISLNK(st.st_mode)) return {EntryKind::symlink, {}};
    return {EntryKind::other, {}};
}

/// Records a directory-listing outcome into `acc`. Truncation and readdir
/// errors are real constraints (`entry_cap`, `enumeration_error`) -- the names
/// read so far are still usable by the caller, but the result is flagged
/// incomplete.
inline void note_listing(yuzu::shared::ConstraintAccumulator& acc, std::string_view os,
                         std::string_view source, const DirListing& l) {
    if (l.walk.enumeration_error) {
        acc.add_failure(make_token(os, source, "enumeration_error"));
        acc.mark_incomplete();
    }
    if (l.walk.truncated) {
        acc.add_failure(make_token(os, source, "entry_cap"));
        acc.mark_incomplete();
    }
}

/// True when the listing read every real entry: not cut at the cap and no readdir
/// error. An incomplete listing's count is only a lower bound, never a fact.
[[nodiscard]] inline bool listing_complete(const DirListing& l) noexcept {
    return !(l.walk.truncated || l.walk.enumeration_error);
}

} // namespace posix

#endif // !defined(_WIN32)

} // namespace yuzu::pkg_inventory
