#pragma once

/// @file command_dedup_quarantine.hpp
/// Filesystem half of the command-dedup corruption recovery (HA WS-0, ADR-2002, issue #3665):
/// move a corrupt `command_dedup.db` aside, and keep only the newest few quarantined copies.
///
/// Factored out of command_dedup_store.cpp so the branches that SQLite itself makes hard to
/// reach (a non-empty sidecar, a sign-shaped or oversized name, a directory named like a
/// quarantine file) can be unit-tested directly (tests/unit/test_command_dedup_store.cpp).
/// It is header-only and has NO sqlite dependency: it only touches names and files.
///
/// Invariants (docs/command-dedup.md invariant 7, "Corruption recovery"):
///  - quarantine_corrupt_db NEVER overwrites an earlier quarantine: on a collision it appends
///    `-<n>`, and if every name is taken it FAILS (nullopt) rather than overwrite.
///  - prune_old_quarantines is COUNT-based (keep the newest kKeepQuarantined groups), not a
///    wall-clock cutoff, and NEVER throws and never removes the file the same recovery just made.
///  - Both only ever touch names of the exact form
///    `<db filename>.corrupt-<digits>[-<digits>][-wal|-shm|-journal]` in the db's own directory.
///  - This is a copy of the idea in agents/plugins/echo/src/echo_db.cpp (quarantine_corrupt_db,
///    #559); hoisting both into agents/shared is a candidate follow-up that has not been filed.

#include <spdlog/spdlog.h>

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <format>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace yuzu::agent::dedup_quarantine {

/// Owner ruling (#3665): only the newest kKeepQuarantined quarantined stores are kept. Each holds
/// up to a ring's worth of serialized terminal CommandResponse frames (status, exit code, short error
/// text; not streamed output, but treated as sensitive as a precaution), and a disk
/// that corrupts the file on every boot would otherwise leave one per boot, forever.
inline constexpr std::size_t kKeepQuarantined = 3;

/// The sidecars SQLite keeps beside a database.
inline constexpr std::string_view kSidecars[] = {"-wal", "-shm", "-journal"};

/// All of `s` is ASCII digits and fits a long long. `from_chars` alone is NOT enough: it accepts a
/// leading '-' (so "-0" would pass a `< 0` check).
inline bool parse_digits(std::string_view s, long long& out) {
    if (s.empty())
        return false;
    for (char c : s) {
        if (c < '0' || c > '9')
            return false;
    }
    const char* last = s.data() + s.size();
    auto r = std::from_chars(s.data(), last, out);
    return r.ec == std::errc{} && r.ptr == last;
}

/// `<stem><epoch>[-<n>]` with an optional -wal/-shm/-journal suffix -> (epoch, n); `stem` is
/// `<db filename>.corrupt-`. Digits only: no sign, no '+', no whitespace, no overflow. Leading
/// zeros are accepted and fold into the canonical key.
inline std::optional<std::pair<long long, long long>> parse_quarantine_name(std::string_view stem,
                                                                           std::string_view name) {
    if (!name.starts_with(stem))
        return std::nullopt;
    name.remove_prefix(stem.size());
    for (std::string_view sfx : kSidecars) {
        if (name.ends_with(sfx)) {
            name.remove_suffix(sfx.size());
            break;
        }
    }
    long long epoch = 0;
    long long n = 0;
    const auto dash = name.find('-');
    if (dash == std::string_view::npos)
        return parse_digits(name, epoch) ? std::optional{std::pair{epoch, 0LL}} : std::nullopt;
    if (!parse_digits(name.substr(0, dash), epoch) || !parse_digits(name.substr(dash + 1), n))
        return std::nullopt;
    return std::pair{epoch, n};
}

/// Move a corrupt database aside to `<path>.corrupt-<epoch>[-n]` and carry any NON-EMPTY
/// -wal/-shm/-journal sidecars with it (`<that name>-wal`, ...). Returns the main file's new path,
/// or nullopt if it could not be moved — the caller then fails (observably, fail-open) and the
/// original file is untouched. An EMPTY sidecar holds no evidence and is removed; a sidecar that
/// cannot be renamed is removed instead, best effort, so the fresh database does not replay a stale
/// WAL belonging to the quarantined file. (If that remove also fails, a stale sidecar can survive
/// beside the fresh file. That needs the main rename to succeed while both sidecar operations fail,
/// which is vanishingly unlikely; echo carries a post-reopen integrity backstop, dedup deliberately
/// does not, because an integrity scan would also discard a usable file.)
///
/// NEVER OVERWRITES an earlier quarantine, even against a concurrent second process: the name is
/// CLAIMED with a hard link, which fails with EEXIST if the name is taken (a check-then-rename would
/// not: rename() replaces its destination on both POSIX and Windows, so two processes recovering in
/// the same second could destroy each other's evidence). The original name is then dropped. If the
/// hard link fails for ANY reason other than the name being taken (a filesystem without hard links,
/// a permission rule), it falls back to check-then-rename, and the concurrent-process guarantee does
/// not hold for that call. If 10,000 names are taken it FAILS (nullopt) rather than overwrite.
///
/// This protects the EVIDENCE only. It does not make recovery safe for two agent daemons on one data
/// dir (unsupported; there is no instance lock): process B can still drop the fresh store that
/// process A just created, leaving A on an orphaned inode.
///
/// `epoch_seconds` is clamped to >= 0: a clock before 1970 would otherwise write `.corrupt--5`,
/// which parse_quarantine_name rejects, so the file could never be pruned. The moved file and its carried
/// sidecars are then set owner-only, best effort (0600 on POSIX; a read-only-attribute toggle on Windows).
inline std::optional<std::filesystem::path> quarantine_corrupt_db(const std::filesystem::path& path,
                                                                 std::int64_t epoch_seconds) {
    const std::int64_t epoch = epoch_seconds < 0 ? 0 : epoch_seconds;
    const auto name_for = [&](int n) {
        std::filesystem::path dest = path;
        dest += n == 0 ? std::format(".corrupt-{}", epoch) : std::format(".corrupt-{}-{}", epoch, n);
        return dest;
    };

    std::optional<std::filesystem::path> claimed;
    bool hard_link_unavailable = false;
    for (int n = 0; n < 10'000; ++n) {
        const auto dest = name_for(n);
        std::error_code lec;
        std::filesystem::create_hard_link(path, dest, lec);
        if (!lec) {
            // The name is ours, atomically. Drop the original name; if that fails the file is still
            // at `path` (also at `dest`), so try to give the claim back and report "could not move".
            // If the give-back also fails a stray `dest` name stays: harmless (it is prunable and
            // names the same inode), but logged.
            std::error_code rec;
            std::filesystem::remove(path, rec);
            if (rec) {
                std::error_code undo;
                std::filesystem::remove(dest, undo);
                if (undo) {
                    spdlog::warn("CommandDedupStore: could not drop {} after claiming {} ({}); the "
                                 "stray name is left in place",
                                 path.string(), dest.string(), undo.message());
                }
                return std::nullopt;
            }
            claimed = dest;
            break;
        }
        if (lec == std::errc::file_exists)
            continue; // taken: try the next suffix
        hard_link_unavailable = true; // no hard links here, or a real error: fall back below
        break;
    }
    if (!claimed && hard_link_unavailable) {
        for (int n = 0; n < 10'000; ++n) {
            const auto dest = name_for(n);
            std::error_code exists_ec;
            if (std::filesystem::exists(dest, exists_ec) || exists_ec)
                continue;
            std::error_code ec;
            std::filesystem::rename(path, dest, ec);
            if (ec)
                return std::nullopt;
            claimed = dest;
            break;
        }
    }
    if (!claimed)
        return std::nullopt;
    const auto& dest = *claimed;
    // Best effort: these files can hold saved command responses, and a corrupt file that never
    // opened successfully may have kept a looser mode (a restored backup, say) because the owner-
    // only chmod runs only after a good open. A no-op for the read-only attribute on Windows.
    const auto owner_only =
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write;
    {
        std::error_code pec;
        if (std::filesystem::is_regular_file(dest, pec)) {
            std::filesystem::permissions(dest, owner_only, std::filesystem::perm_options::replace,
                                         pec);
        }
    }
    for (std::string_view sfx : kSidecars) {
        std::filesystem::path side = path;
        side += std::string{sfx};
        std::error_code ec2;
        const bool present = std::filesystem::exists(side, ec2);
        if (ec2) {
            // Cannot tell whether it is there: drop it rather than leave a possibly stale sidecar
            // beside the fresh database. Best effort.
            std::error_code ec3;
            std::filesystem::remove(side, ec3);
            continue;
        }
        if (!present)
            continue;
        std::error_code size_ec;
        if (std::filesystem::file_size(side, size_ec) == 0) {
            std::filesystem::remove(side, ec2);
            continue;
        }
        std::filesystem::path side_dest = dest;
        side_dest += std::string{sfx};
        std::filesystem::rename(side, side_dest, ec2);
        if (ec2) {
            std::error_code ec3;
            std::filesystem::remove(side, ec3);
        } else {
            std::error_code pec;
            std::filesystem::permissions(side_dest, owner_only,
                                         std::filesystem::perm_options::replace, pec);
        }
    }
    return dest;
}

/// Keep only the newest kKeepQuarantined quarantined stores in the db's directory. COUNT-based,
/// not a wall-clock cutoff. Groups are ordered by the (epoch, n) parsed from the NAME, which a
/// backward clock step can mis-order, so `just_created` (the file this very recovery made) is
/// never a candidate. Best effort and NEVER throws: a failed remove is logged and left for the next
/// recovery; an unlistable directory is logged and nothing is deleted.
inline void prune_old_quarantines(const std::filesystem::path& db_path,
                                  const std::filesystem::path& just_created) noexcept {
    try {
        const std::string stem = db_path.filename().string() + ".corrupt-";
        const auto keep_key = parse_quarantine_name(stem, just_created.filename().string());
        auto dir = db_path.parent_path();
        if (dir.empty())
            dir = ".";

        std::map<std::pair<long long, long long>, std::vector<std::filesystem::path>> groups;
        std::error_code ec;
        for (std::filesystem::directory_iterator it(dir, ec), end; !ec && it != end;
             it.increment(ec)) {
            if (auto key = parse_quarantine_name(stem, it->path().filename().string()))
                groups[*key].push_back(it->path());
        }
        if (ec) {
            spdlog::warn("CommandDedupStore: could not list {} to prune old quarantined stores: {}",
                         dir.string(), ec.message());
            return;
        }
        if (groups.size() <= kKeepQuarantined)
            return;
        std::size_t excess = groups.size() - kKeepQuarantined;
        for (const auto& [key, files] : groups) { // ascending: oldest name first
            if (excess == 0)
                break;
            if (keep_key && key == *keep_key)
                continue;
            for (const auto& f : files) {
                std::error_code rec;
                std::filesystem::remove(f, rec);
                if (rec) {
                    spdlog::warn("CommandDedupStore: could not remove old quarantined store {}: {}",
                                 f.string(), rec.message());
                } else {
                    spdlog::info("CommandDedupStore: removed old quarantined store {} (keeping "
                                 "the newest {})",
                                 f.string(), kKeepQuarantined);
                }
            }
            --excess;
        }
    } catch (const std::exception& e) {
        spdlog::warn("CommandDedupStore: pruning old quarantined stores stopped early: {}",
                     e.what());
    } catch (...) {
        spdlog::warn("CommandDedupStore: pruning old quarantined stores stopped early");
    }
}

} // namespace yuzu::agent::dedup_quarantine
