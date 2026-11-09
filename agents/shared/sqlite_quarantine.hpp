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

/// Test seam for the two filesystem steps whose failure is hard to provoke on a real disk. An
/// empty member means the real `std::filesystem` call; production never sets one.
struct FsOps {
    /// Claim `to` as a new name for `from` (default: `std::filesystem::create_hard_link`).
    std::function<void(const std::filesystem::path& from, const std::filesystem::path& to,
                       std::error_code&)>
        link;
    /// Move a sidecar (default: `std::filesystem::rename`).
    std::function<void(const std::filesystem::path& from, const std::filesystem::path& to,
                       std::error_code&)>
        move;
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
/// hard links, or the original name could not be dropped; `notes`, when given, receives why and
/// anything left behind. `epoch_seconds` is clamped to >= 0 (a pre-1970 clock would otherwise
/// write `.corrupt--5`, which the dedup prune parser rejects, so the file could never be pruned).
[[nodiscard]] inline std::optional<std::filesystem::path>
claim_quarantine_name(const std::filesystem::path& file, std::int64_t epoch_seconds,
                      std::string_view suffix, std::vector<std::string>* notes = nullptr,
                      const FsOps& ops = {}) {
    namespace fs = std::filesystem;
    const std::int64_t epoch = epoch_seconds < 0 ? 0 : epoch_seconds;
    const auto note = [&](std::string text) {
        if (notes)
            notes->push_back(std::move(text));
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
        // The name is ours, atomically. Drop the original name; if that fails the file is still at
        // `file` (also at `dest`), so give the claim back and report "could not move".
        std::error_code rec;
        fs::remove(file, rec);
        if (rec) {
            std::error_code undo;
            fs::remove(dest, undo);
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
/// fail and the sidecar is removed under the rule above: such a writer can remove the sidecar
/// directly, and the packaged Windows state directory admits no such writer. And on Windows the
/// copy fallback creates its file with the directory's inherited ACL (`secure` there is only the
/// read-only attribute; a rename keeps the source's DACL), so a copied sidecar is as readable as
/// the state directory, which the packaged install restricts to SYSTEM, Administrators and the
/// agent account.
[[nodiscard]] inline QuarantineResult quarantine_corrupt_db(const std::filesystem::path& path,
                                                           std::int64_t epoch_seconds,
                                                           const FsOps& ops = {}) {
    namespace fs = std::filesystem;
    QuarantineResult result;
    result.dest = claim_quarantine_name(path, epoch_seconds, ".corrupt-", &result.notes, ops);
    if (!result.dest)
        return result;
    const fs::path& dest = *result.dest;
    const auto owner_only = fs::perms::owner_read | fs::perms::owner_write;
    const auto secure = [&](const fs::path& p) {
        std::error_code pec;
        if (fs::is_regular_file(p, pec))
            fs::permissions(p, owner_only, fs::perm_options::replace, pec);
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
