#pragma once

/// @file sqlite_quarantine.hpp
/// The one filesystem primitive for setting a SQLite database file aside as evidence: used by the
/// command-dedup store (a corrupt `command_dedup.db`), the Echo store (a corrupt `echo.db`) and
/// the legacy-adoption step (a planted `echo.db`). Header-only, no sqlite dependency, no logging
/// and no windows.h (agents/shared convention): every function RETURNS notes and the caller logs
/// them.
///
/// GUARANTEE: nothing here ever overwrites an existing file at a quarantine name. A name is
/// CLAIMED with a hard link (`create_hard_link` fails with EEXIST when the name is taken, where a
/// check-then-`rename` would not: `rename` replaces its destination on POSIX and Windows, so two
/// recoveries in the same second could destroy each other's evidence), then the original name is
/// dropped. PRECONDITION: the directory's filesystem supports hard links (NTFS, ReFS, ext4, xfs,
/// APFS, tmpfs all do). Without hard links the claim FAILS CLOSED (nullopt plus a note naming the
/// directory): there is deliberately no check-then-rename fallback, and callers refuse to proceed
/// rather than risk destroying evidence. Only the main file's name is claimed this way; a
/// sidecar's quarantine name is derived from that exclusively claimed name (`<claimed>-wal`), so
/// the plain exists-then-rename step used for sidecars cannot collide with another recovery.
/// An interruption between the link and the remove (a crash, or a failed undo) leaves the file
/// under both names: a POSIX open quarantines it again under the next free name, while the
/// Windows Echo open refuses until one of the two names is removed (the second link reads as a
/// planted file; docs/user-manual/upgrading.md gives the remedy).
///
/// BINDING: a claim moves only the REGULAR FILE that was judged, never a name. `link(2)` follows
/// a symbolic link at the source on macOS (the claim would link the link's target) and moves the
/// link itself on Linux (a following chmod would then reach the target), and a second recovery
/// racing this one can replace the name with a fresh healthy file between the verdict and the
/// move. So the source is examined without following links before the claim (a link, a
/// directory or an absent name is refused), the claimed name is examined the same way after the
/// link and must be the same inode (POSIX: device + inode by `lstat`; the caller may pass the
/// identity it read while its connection was still open, which binds the move to the verdict
/// itself), the original name is re-examined right before it is dropped, and every mode change
/// is applied only to a regular file and without following a link. A mismatch releases the claim
/// and fails closed. Windows has no `lstat`-style identity here (this header includes no
/// windows.h), so there only the no-follow regular-file checks bind the claim: a replaced regular
/// file is a recorded residual on that platform (SQLite holds its files without
/// FILE_SHARE_DELETE, so a live database another process has open cannot lose its name there).
/// Two residuals remain on POSIX. The original is re-examined and then dropped by name, and
/// POSIX has no unlink-if-same-inode, so a second recovery that drops the name AND creates a new
/// file at it inside that gap loses its file (two agent processes on one data directory are
/// unsupported). And a HARD link planted at the name is a regular file with its target's
/// identity, so it is judged, claimed and secured as that target: the open that judged it had
/// already used it as the database (pre-existing; Linux protected_hardlinks refuses a link to a
/// file the planter does not own, and the packaged POSIX data directory is root-owned).
///
/// Names have the exact form `<file><suffix><epoch>[-<n>]` (suffix `.corrupt-` or `.planted-`),
/// which the dedup store's prune parser relies on.

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <format>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace yuzu::shared::sqlite_quarantine {

/// The sidecars SQLite keeps beside a database.
inline constexpr std::string_view kSidecars[] = {"-wal", "-shm", "-journal"};

/// How many `-<n>` names a claim tries before it gives up (fails rather than overwrite).
inline constexpr int kMaxClaimAttempts = 10'000;

/// Wall-clock seconds since the epoch: the `epoch_seconds` every caller passes to the functions
/// below.
inline std::int64_t now_epoch_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

/// The identity of a directory entry read WITHOUT following a link: device and inode on POSIX.
/// On Windows there is none (no `lstat` without windows.h): `file_identity` is nullopt there and
/// two nullopts compare equal, so the regular-file checks are the whole binding on that platform.
struct FileIdentity {
    std::uintmax_t device = 0;
    std::uintmax_t inode = 0;
    bool operator==(const FileIdentity&) const = default;
};

/// `lstat` identity of `p`, or nullopt when it cannot be read (absent, unreadable, or Windows).
inline std::optional<FileIdentity> file_identity(const std::filesystem::path& p) noexcept {
#ifdef _WIN32
    (void)p;
    return std::nullopt;
#else
    struct stat st {};
    if (::lstat(p.c_str(), &st) != 0)
        return std::nullopt;
    return FileIdentity{static_cast<std::uintmax_t>(st.st_dev),
                        static_cast<std::uintmax_t>(st.st_ino)};
#endif
}

/// True only for a regular file examined without following a link (a symlink, a directory, an
/// absent name or an unreadable one is false).
inline bool is_regular_file_no_follow(const std::filesystem::path& p) noexcept {
    std::error_code ec;
    const auto st = std::filesystem::symlink_status(p, ec);
    return !ec && std::filesystem::is_regular_file(st);
}

/// Test seam for the filesystem steps whose failure is hard to provoke on a real disk. An empty
/// member means the real `std::filesystem` call; production never sets one.
struct FsOps {
    /// Claim `to` as a new name for `from` (default: `std::filesystem::create_hard_link`).
    std::function<void(const std::filesystem::path& from, const std::filesystem::path& to,
                       std::error_code&)>
        link;
    /// Move a sidecar (default: `std::filesystem::rename`).
    std::function<void(const std::filesystem::path& from, const std::filesystem::path& to,
                       std::error_code&)>
        move;
    /// Drop a name: the original after a claim, or the claim itself when it is given back
    /// (default: `std::filesystem::remove`).
    std::function<void(const std::filesystem::path& name, std::error_code&)> remove;
};

struct QuarantineResult {
    /// The main file's new path, or nullopt when it could not be moved (the original is then
    /// untouched).
    std::optional<std::filesystem::path> dest;
    /// Everything the caller should log: a sidecar that was copied or dropped, a stray name left
    /// behind, why a claim failed.
    std::vector<std::string> notes;
};

/// Move ONE file (no sidecars) to `<file><suffix><epoch>[-<n>]`, never overwriting. Returns the
/// new path, or nullopt (original untouched) when no name could be claimed, the filesystem has no
/// hard links, the name is not a regular file, the claim did not land on the file that was judged
/// (see BINDING above), or the original name could not be dropped; `notes`, when given, receives
/// why and anything left behind. `judged`, when given, is the identity the caller read while it
/// still held the file open (`file_identity`); otherwise the name is read here, just before the
/// claim. `epoch_seconds` is clamped to >= 0 (a pre-1970 clock would otherwise write
/// `.corrupt--5`, which the dedup prune parser rejects, so the file could never be pruned).
[[nodiscard]] inline std::optional<std::filesystem::path>
claim_quarantine_name(const std::filesystem::path& file, std::int64_t epoch_seconds,
                      std::string_view suffix, std::vector<std::string>* notes = nullptr,
                      const FsOps& ops = {},
                      const std::optional<FileIdentity>& judged = std::nullopt) {
    namespace fs = std::filesystem;
    const std::int64_t epoch = epoch_seconds < 0 ? 0 : epoch_seconds;
    const auto note = [&](std::string text) {
        if (notes)
            notes->push_back(std::move(text));
    };
    const auto rm = [&](const fs::path& name, std::error_code& ec) {
        if (ops.remove)
            ops.remove(name, ec);
        else
            fs::remove(name, ec);
    };
    // Only a regular file is ever claimed: a link here would be linked through (macOS) or carried
    // as a link and chmodded through (Linux); a directory cannot be hard-linked anyway.
    if (!is_regular_file_no_follow(file)) {
        note(std::format("{} is not a regular file (a link, a directory, or gone), so it was not "
                         "claimed and was left in place",
                         file.string()));
        return std::nullopt;
    }
    const std::optional<FileIdentity> expected = judged ? judged : file_identity(file);
    if (judged && file_identity(file) != judged) {
        note(std::format("{} is no longer the file that was judged (replaced between the check "
                         "and the move), so it was not claimed and was left in place",
                         file.string()));
        return std::nullopt;
    }
    // The claimed name, and the original right before it is dropped, must both still be the judged
    // regular file; otherwise the claim is released and nothing is moved.
    const auto still_judged = [&](const fs::path& p) {
        return is_regular_file_no_follow(p) && file_identity(p) == expected;
    };
    for (int n = 0; n < kMaxClaimAttempts; ++n) {
        fs::path dest = file;
        dest += n == 0 ? std::format("{}{}", suffix, epoch) : std::format("{}{}-{}", suffix, epoch, n);
        std::error_code lec;
        if (ops.link)
            ops.link(file, dest, lec);
        else
            fs::create_hard_link(file, dest, lec);
        if (lec == std::errc::file_exists)
            continue; // taken: try the next suffix
        if (lec) {
            // No hard links on this filesystem, a permission rule, or the source is gone. Never
            // fall back to rename: that can overwrite an earlier quarantine.
            note(std::format("could not claim a quarantine name for {} ({}); the directory's "
                             "filesystem must support hard links, so the file was left in place",
                             file.string(), lec.message()));
            return std::nullopt;
        }
        // The name is ours, atomically. It must be the judged file (not a link's target, not a
        // link, not a fresh file another recovery put at the name), and so must the original at
        // the moment it is dropped. On a mismatch release the claim: the judged file, if it is
        // still there, stays at `file`.
        if (!still_judged(dest) || !still_judged(file)) {
            std::error_code undo;
            rm(dest, undo);
            note(std::format("{} is not the file that was judged (a link was swapped in, or "
                             "another recovery replaced it between the check and the move); the "
                             "claim {} was released and nothing was moved",
                             file.string(), dest.string()));
            if (undo) {
                note(std::format("could not release the claim {} ({}); the stray name is left in "
                                 "place",
                                 dest.string(), undo.message()));
            }
            return std::nullopt;
        }
        // Drop the original name; if that fails the file is still at `file` (also at `dest`), so
        // give the claim back and report "could not move".
        std::error_code rec;
        rm(file, rec);
        if (rec) {
            std::error_code undo;
            rm(dest, undo);
            note(std::format("could not drop {} after claiming {} ({})", file.string(),
                             dest.string(), rec.message()));
            if (undo) {
                note(std::format("could not release the claim {} ({}); the stray name is left in "
                                 "place",
                                 dest.string(), undo.message()));
            }
            return std::nullopt;
        }
        return dest;
    }
    note(std::format("every quarantine name for {} is taken ({} tried); the file was left in place",
                     file.string(), kMaxClaimAttempts));
    return std::nullopt;
}

/// Move a corrupt database aside to `<path>.corrupt-<epoch>[-n]` and carry its non-empty
/// -wal/-shm/-journal sidecars with it (`<that name>-wal`, ...). `dest` nullopt = the main file
/// could not be moved (the original is untouched and the caller MUST fail closed). An EMPTY
/// sidecar holds no evidence and is removed. A sidecar that cannot be renamed is COPIED to its
/// quarantine name (never over an existing file) and the original then removed, so the fresh
/// database can neither replay a stale WAL nor lose the evidence; if even the copy fails the
/// original is still removed (a note says the evidence was lost) because replaying it is worse.
/// If that remove also fails a stale sidecar survives beside the fresh file: the Echo caller's
/// post-reopen integrity check is the backstop. The moved files are then set owner-only, best
/// effort (0600 on POSIX; a read-only-attribute toggle on Windows).
/// Two recorded limits of the sidecar step. It is exists-then-rename on the derived name, so a
/// writer of the directory who squats `<claimed>-wal` ahead of time makes the rename and the copy
/// fail and the sidecar is removed under the rule above, its content not kept. And on Windows the
/// copy fallback creates its file with the directory's inherited ACL (`secure` there is only the
/// read-only attribute; a rename keeps the source's DACL), so a copied sidecar is as readable as
/// the directory's inherited ACL makes it. A caller that protects its database with its own DACL
/// re-applies it to the quarantine set itself, as the Echo caller does (echo_db.cpp,
/// secure_quarantined_sidecars); this header does not. `judged` is the main file's identity the
/// caller read while it still held the file open (BINDING above); nullopt reads it here.
[[nodiscard]] inline QuarantineResult
quarantine_corrupt_db(const std::filesystem::path& path, std::int64_t epoch_seconds,
                      const FsOps& ops = {},
                      const std::optional<FileIdentity>& judged = std::nullopt) {
    namespace fs = std::filesystem;
    QuarantineResult result;
    result.dest =
        claim_quarantine_name(path, epoch_seconds, ".corrupt-", &result.notes, ops, judged);
    if (!result.dest)
        return result;
    const fs::path& dest = *result.dest;
    // Only a regular file, examined and changed without following a link: a sidecar that was a
    // symlink travels as a link and its target's mode is never touched. POSIX opens the name
    // O_NOFOLLOW and changes the mode through that handle (fchmodat's AT_SYMLINK_NOFOLLOW is
    // ENOTSUP on glibc before 2.32, which would silently skip the change).
    const auto secure = [&](const fs::path& p) {
        if (!is_regular_file_no_follow(p))
            return;
#ifdef _WIN32
        std::error_code pec;
        fs::permissions(p, fs::perms::owner_read | fs::perms::owner_write,
                        fs::perm_options::replace | fs::perm_options::nofollow, pec);
#else
        const int fd = ::open(p.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0)
            return;
        struct stat st {};
        if (::fstat(fd, &st) == 0 && S_ISREG(st.st_mode))
            ::fchmod(fd, S_IRUSR | S_IWUSR);
        ::close(fd);
#endif
    };
    secure(dest);

    for (std::string_view sfx : kSidecars) {
        fs::path side = path;
        side += std::string{sfx};
        std::error_code ec;
        const bool present = fs::exists(side, ec);
        if (ec) {
            // Cannot tell whether it is there: drop it rather than leave a possibly stale sidecar
            // beside the fresh database. Best effort, and the caller is told.
            std::error_code rm;
            fs::remove(side, rm);
            result.notes.push_back(std::format(
                "could not examine {} ({}); removed best effort so the fresh database cannot "
                "replay it{}",
                side.string(), ec.message(),
                rm ? std::format(" (the remove failed too: {})", rm.message()) : std::string{}));
            continue;
        }
        if (!present)
            continue;
        std::error_code size_ec;
        if (fs::file_size(side, size_ec) == 0 && !size_ec) {
            fs::remove(side, ec);
            continue;
        }
        fs::path side_dest = dest;
        side_dest += std::string{sfx};
        // Never rename over an existing name (rename replaces its destination).
        std::error_code taken_ec;
        const bool taken = fs::exists(side_dest, taken_ec) || taken_ec;
        std::error_code mec = std::make_error_code(std::errc::file_exists);
        if (!taken) {
            mec.clear();
            if (ops.move)
                ops.move(side, side_dest, mec);
            else
                fs::rename(side, side_dest, mec);
        }
        if (!mec) {
            secure(side_dest);
            continue;
        }
        // Rename failed: preserve by copy (fails rather than overwrite), then drop the original.
        std::error_code cec;
        fs::copy_file(side, side_dest, fs::copy_options::none, cec);
        if (cec) {
            result.notes.push_back(std::format(
                "could not preserve {} as {} ({}); its content is not kept", side.string(),
                side_dest.string(), cec.message()));
        } else {
            secure(side_dest);
            result.notes.push_back(std::format("copied {} to {} because it could not be renamed "
                                               "({})",
                                               side.string(), side_dest.string(), mec.message()));
        }
        std::error_code rm;
        fs::remove(side, rm);
        if (rm) {
            result.notes.push_back(std::format("could not remove {} ({}); a stale sidecar may "
                                               "remain beside the fresh database",
                                               side.string(), rm.message()));
        }
    }
    return result;
}

} // namespace yuzu::shared::sqlite_quarantine
