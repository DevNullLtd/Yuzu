// echo_db_legacy_rename.hpp -- adopt a pre-rename tar.db as echo.db.
//
// Pre-rename install helper (kept while a pre-rename tar.db can still exist). Before the Echo rename the
// activity-record database lived at <data_dir>/tar.db; it now lives at <data_dir>/echo.db. The
// file keeps its DACL / mode and content, so adoption is a rename, nothing else.
//
// ONE caller: agent core at boot (agents/core/src/agent.cpp), after the KV store opens and
// before any plugin init or dispatch (the plugin scan only registers descriptors; no plugin
// opens a database before init). That placement is the exclusion within the process: no
// process-wide lock exists across plugin dylibs, so no plugin ever adopts, and nothing in this
// process has the database open while it is moved. It does not exclude a predecessor process
// still shutting down during a service restart (the step runs before the Guardian instance
// lock): on Windows its open handle can fail the rename, which is logged and resumed on the
// next start. EchoDatabase::open() refuses to create a fresh echo.db beside an unadopted
// tar.db, so a failed adoption fails closed instead of booting with default config. The caller
// defers adoption entirely while the plugin dir holds only the retired tar plugin (an OTA
// replaces the agent binary alone): the next start after echo.<ext> is installed adopts.
//
// Order is load-bearing: sidecars (-journal, -wal, -shm) move BEFORE the main file. An
// interrupted adoption therefore always looks like "tar.db present, echo.db absent" and resumes
// on the next boot, and echo.db can never be opened while its WAL still carries the old name.
//
// Adoption-intent marker (#6752). A resume must not pair a NEWER tar.db with an OLDER echo.db WAL:
// if an older agent is run against tar.db between an interruption and the next boot, writes, and
// cleanly checkpoints and deletes its WAL, replaying the echo.db WAL over that file would lose or
// corrupt Echo history. So before the FIRST sidecar move the helper durably writes
// <data_dir>/echo.db.adopting holding tar.db's size and mtime at that moment, and removes it after
// the main-file rename. On the next boot:
//   - tar.db present, an echo.db sidecar present, marker present and equal to tar.db's current
//     size and mtime: nothing has touched tar.db since the sidecars moved; resume as normal.
//   - the same with the marker ABSENT or recording a different tar.db: the echo.db sidecar is not
//     provably this adoption's own (the marker is written before every move it guards), so adoption
//     fails closed, naming both files, and moves nothing; EchoDatabase::open() then refuses until
//     the operator resolves the two files.
// The marker is a plain file written with write_file_atomic (fsync'd on POSIX; on Windows the
// shared writer documents no flush-by-handle, so a power loss right after the write can lose the
// marker there, which fails closed rather than open). A marker left behind once tar.db is gone (the
// removal after the rename failed) is deleted at the next boot. An older agent that never learned
// of the marker still cannot slip through, because the comparison is against tar.db itself.
//
// Open-path ordering (settles the overlap with the v10 schema migration): adoption runs in agent
// core (agents/core/src/agent.cpp) before any plugin initialises, and the v10 migration runs inside
// EchoDatabase::open() from EchoPlugin::init, so the marker is already gone before open() runs and
// a v10 failure never touches it.
//
// If both main files exist they are two independent databases (an agent downgraded after the
// rename, then upgraded again). Nothing is touched: echo.db wins, tar.db and its sidecars are
// left for the operator, and one warning names them. Old tar.db.corrupt-* quarantine files are
// never touched.
//
// A sidecar present at BOTH names while tar.db is being adopted (for example a downgrade wrote a
// fresh tar.db-wal beside an already-moved echo.db-wal) cannot be paired safely: moving tar.db
// anyway would open it with a foreign WAL and strand the legacy WAL's committed rows. Adoption
// fails closed there and moves nothing further; tar.db stays, echo.db stays absent, and
// EchoDatabase::open() refuses until the operator resolves the two files. Without a legacy main
// file there is nothing to adopt, so a stray legacy sidecar is only warned about and left: renamed
// onto a live echo.db, a leftover tar.db-wal would be replayed by SQLite over current data (it
// validates a WAL by its own checksum chain, never against the main file). Every resumable state
// has tar.db present, because sidecars move before the main file.
#pragma once

#include <expected>
#include <filesystem>
#include <format>
#include <fstream>
#include <optional>
#include <string>
#include <system_error>

#include <spdlog/spdlog.h>

#include <atomic_file_write.hpp> // yuzu::shared::write_file_atomic: the fsync'd marker write

namespace yuzu::agent {

namespace detail {

/// What the marker records about the legacy main file: its size and mtime.
[[nodiscard]] inline std::expected<std::string, std::string>
legacy_echo_fingerprint(const std::filesystem::path& legacy) {
    namespace fs = std::filesystem;
    std::error_code ec;
    const auto size = fs::file_size(legacy, ec);
    if (ec)
        return std::unexpected(std::format("cannot stat {}: {}", legacy.string(), ec.message()));
    const auto mtime = fs::last_write_time(legacy, ec);
    if (ec)
        return std::unexpected(std::format("cannot stat {}: {}", legacy.string(), ec.message()));
    return std::format("{} {}\n", size, mtime.time_since_epoch().count());
}

} // namespace detail

[[nodiscard]] inline std::expected<void, std::string>
adopt_legacy_echo_db(const std::filesystem::path& echo_db) {
    namespace fs = std::filesystem;
    constexpr const char* kSidecars[] = {"-journal", "-wal", "-shm"};
    const fs::path legacy = echo_db.parent_path() / "tar.db";

    std::error_code ec;
    const bool echo_present = fs::exists(echo_db, ec);
    if (ec)
        return std::unexpected(std::format("cannot stat {}: {}", echo_db.string(), ec.message()));
    const bool legacy_present = fs::exists(legacy, ec);
    if (ec)
        return std::unexpected(std::format("cannot stat {}: {}", legacy.string(), ec.message()));

    // <data_dir>/echo.db.adopting: the adoption-intent marker (path only; no I/O here).
    fs::path marker = echo_db;
    marker += ".adopting";

    if (echo_present && legacy_present) {
        spdlog::warn("Legacy {} exists beside {}: two independent databases. {} is used; the legacy "
                     "file and its sidecars are left untouched for the operator",
                     legacy.string(), echo_db.string(), echo_db.string());
        return {};
    }

    // No legacy main file: nothing to adopt. A stray legacy sidecar is left where it is, never
    // moved onto echo.db (see the header comment).
    if (!legacy_present) {
        // A marker outliving the main-file rename (its removal failed) is spent: delete it, or a
        // later downgrade that recreates tar.db could be mistaken for this adoption's resume.
        std::error_code mec;
        if (fs::remove(marker, mec); mec)
            spdlog::warn("Cannot remove the spent adoption marker {}: {}", marker.string(),
                         mec.message());
        for (const char* suffix : kSidecars) {
            fs::path stray = legacy;
            stray += suffix;
            const bool stray_present = fs::exists(stray, ec);
            if (ec)
                return std::unexpected(
                    std::format("cannot stat {}: {}", stray.string(), ec.message()));
            if (stray_present)
                spdlog::warn("Legacy {} left in place: there is no {} to adopt, and a stray "
                             "sidecar is never moved onto {}",
                             stray.string(), legacy.string(), echo_db.string());
        }
        return {};
    }

    // Resume safety (#6752): an echo.db sidecar whose legacy twin is absent was either moved by an
    // earlier run of THIS adoption or is stale. It is provably ours only when the marker records
    // tar.db exactly as it is now (see the header comment); otherwise fail closed, moving nothing.
    const auto fingerprint = detail::legacy_echo_fingerprint(legacy);
    if (!fingerprint)
        return std::unexpected(fingerprint.error());
    // An absent or unreadable marker both read as "no marker". The read is capped: a fingerprint is
    // under 64 bytes, so a longer file can only mismatch. The stream is closed before the marker is
    // rewritten or removed below (on Windows an open handle blocks both).
    std::optional<std::string> recorded;
    {
        std::ifstream in(marker, std::ios::binary);
        if (in) {
            std::string buf(256, '\0');
            in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
            buf.resize(static_cast<std::size_t>(in.gcount()));
            recorded = std::move(buf);
        }
    }
    const bool marker_matches = recorded && *recorded == *fingerprint;
    if (!marker_matches) {
        for (const char* suffix : kSidecars) {
            fs::path from = legacy;
            from += suffix;
            fs::path to = echo_db;
            to += suffix;
            const bool from_present = fs::exists(from, ec);
            if (ec)
                return std::unexpected(
                    std::format("cannot stat {}: {}", from.string(), ec.message()));
            const bool to_present = fs::exists(to, ec);
            if (ec)
                return std::unexpected(
                    std::format("cannot stat {}: {}", to.string(), ec.message()));
            if (to_present && !from_present)
                return std::unexpected(std::format(
                    "cannot adopt {}: {} exists but {}, so it cannot be shown to belong to this "
                    "adoption (it could be an older database's log); nothing was moved, resolve "
                    "{} by hand",
                    legacy.string(), to.string(),
                    recorded ? std::format("{} records a different {}", marker.string(),
                                           legacy.string())
                             : std::format("no adoption marker {} exists", marker.string()),
                    to.string()));
        }
    }

    // Sidecars first. A source that does not exist is already moved (or never was): success.
    bool marker_written = marker_matches;
    for (const char* suffix : kSidecars) {
        // path::operator+= appends in the native character type; string() + suffix would narrow
        // a wide Windows path through the ANSI code page first.
        fs::path from = legacy;
        from += suffix;
        fs::path to = echo_db;
        to += suffix;
        if (!fs::exists(from, ec)) {
            if (ec)
                return std::unexpected(
                    std::format("cannot stat {}: {}", from.string(), ec.message()));
            continue;
        }
        // Never overwrite: an overwritten -wal would lose committed rows. The legacy main file is
        // still to be adopted, so a collision cannot be resolved here (the main file would be
        // paired with the wrong WAL): fail closed and move nothing further.
        const bool to_present = fs::exists(to, ec);
        if (ec)
            return std::unexpected(std::format("cannot stat {}: {}", to.string(), ec.message()));
        if (to_present)
            return std::unexpected(
                std::format("cannot adopt {}: {} and {} both exist; resolve them by hand",
                            legacy.string(), from.string(), to.string()));
        // Record the intent durably BEFORE the first sidecar leaves its name.
        if (!marker_written) {
            if (auto w = yuzu::shared::write_file_atomic(marker, *fingerprint); !w)
                return std::unexpected(std::format("cannot adopt {}: cannot record the adoption "
                                                   "marker {}: {}",
                                                   legacy.string(), marker.string(),
                                                   w.error().message));
            marker_written = true;
        }
        fs::rename(from, to, ec);
        if (ec)
            return std::unexpected(std::format("cannot move {} to {}: {}", from.string(),
                                               to.string(), ec.message()));
        spdlog::info("Adopted legacy {} as {}", from.string(), to.string());
    }

    fs::rename(legacy, echo_db, ec);
    if (ec)
        return std::unexpected(std::format("cannot move {} to {}: {}", legacy.string(),
                                           echo_db.string(), ec.message()));
    // Adoption is complete; the marker is spent. A failed removal is retried at the next boot.
    std::error_code mec;
    if (fs::remove(marker, mec); mec)
        spdlog::warn("Cannot remove the spent adoption marker {}: {}", marker.string(),
                     mec.message());
    spdlog::info("Adopted legacy {} as {}", legacy.string(), echo_db.string());
    return {};
}

} // namespace yuzu::agent
