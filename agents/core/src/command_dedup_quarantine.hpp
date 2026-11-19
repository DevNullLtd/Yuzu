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
///  - The move itself is shared with agents/plugins/echo/src/echo_db.cpp (#559, #6914). This
///    store passes no judged identity (the connection that failed is already closed), so the
///    shared move binds the claim to the file at the name at claim time (POSIX); Echo passes
///    the identity it read right after its open. Windows has no identity in either caller.

#include <spdlog/spdlog.h>

#include <sqlite_quarantine.hpp>

#include <cstddef>
#include <filesystem>

namespace yuzu::agent::dedup_quarantine {

/// Owner ruling (#3665): only the newest kKeepQuarantined quarantined stores are kept. Each holds
/// up to a ring's worth of serialized terminal CommandResponse frames (status, exit code, short error
/// text; not streamed output, but treated as sensitive as a precaution), and a disk
/// that corrupts the file on every boot would otherwise leave one per boot, forever.
inline constexpr std::size_t kKeepQuarantined = 3;

/// The sidecars SQLite keeps beside a database (one list, shared with the quarantine primitive).
using yuzu::shared::sqlite_quarantine::kSidecars;

/// The name grammar and the count-based prune live in the shared primitive (the Echo store prunes
/// its own quarantines with the same code).
using yuzu::shared::sqlite_quarantine::parse_digits;
using yuzu::shared::sqlite_quarantine::parse_quarantine_name;

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

/// Keep only the newest kKeepQuarantined quarantined stores in the db's directory
/// (yuzu::shared::sqlite_quarantine::prune_old_quarantines, which owns the contract). Best effort
/// and NEVER throws: a failed remove is logged and left for the next recovery; an unlistable
/// directory is logged and nothing is deleted.
inline void prune_old_quarantines(const std::filesystem::path& db_path,
                                  const std::filesystem::path& just_created) noexcept {
    try {
        const auto pruned = yuzu::shared::sqlite_quarantine::prune_old_quarantines(
            db_path, just_created, kKeepQuarantined);
        for (const auto& f : pruned.removed)
            spdlog::info("CommandDedupStore: removed old quarantined store {} (keeping the "
                         "newest {})",
                         f.string(), kKeepQuarantined);
        for (const auto& note : pruned.notes)
            spdlog::warn("CommandDedupStore: {}", note);
    } catch (...) { // logging must not break the recovery
    }
}

} // namespace yuzu::agent::dedup_quarantine
