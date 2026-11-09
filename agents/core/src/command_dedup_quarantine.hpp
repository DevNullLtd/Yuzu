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
///    `-<n>`, and if every name is taken, or the filesystem has no hard links, it FAILS (nullopt)
///    rather than overwrite (agents/shared/sqlite_quarantine.hpp).
///  - prune_old_quarantines is COUNT-based (keep the newest kKeepQuarantined groups), not a
///    wall-clock cutoff, and NEVER throws and never removes the file the same recovery just made.
///  - Both only ever touch names of the exact form
///    `<db filename>.corrupt-<digits>[-<digits>][-wal|-shm|-journal]` in the db's own directory.
///  - The move itself is shared with agents/plugins/echo/src/echo_db.cpp (#559, #6914).

#include <spdlog/spdlog.h>

#include <sqlite_quarantine.hpp>

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

/// The sidecars SQLite keeps beside a database (one list, shared with the quarantine primitive;
/// declared here, ahead of parse_quarantine_name, which iterates it).
using yuzu::shared::sqlite_quarantine::kSidecars;

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

/// Move a corrupt database aside to `<path>.corrupt-<epoch>[-n]`, carrying its sidecars: the shared
/// primitive (agents/shared/sqlite_quarantine.hpp), which owns the no-overwrite and copy-preserve
/// contract. `dest` nullopt = it could not be moved, the original is untouched, and the caller
/// degrades (observably, fail-open). The caller logs `notes`.
///
/// This protects the EVIDENCE only. It does not make recovery safe for two agent daemons on one data
/// dir (unsupported; no instance lock covers the dedup store, and the Guardian boot-epoch lock
/// guards only the epoch claim): process B can still drop the fresh store that process A just
/// created, leaving A on an orphaned inode.
using yuzu::shared::sqlite_quarantine::QuarantineResult;
using yuzu::shared::sqlite_quarantine::quarantine_corrupt_db;

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
