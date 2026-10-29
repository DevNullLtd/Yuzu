// echo_db_legacy_rename.hpp -- adopt a pre-rename tar.db as echo.db.
//
// Upgrade-window helper (removed with the other legacy-name shims). Before the Echo rename the
// activity-record database lived at <data_dir>/tar.db; it now lives at <data_dir>/echo.db. The
// file keeps its DACL / mode and content, so adoption is a rename, nothing else.
//
// ONE caller: agent core at boot (agents/core/src/agent.cpp), after the KV store opens and
// before any plugin init or dispatch (the plugin scan only registers descriptors; no plugin
// opens a database before init). That placement is the exclusion: no process-wide lock exists
// across plugin dylibs, so no plugin ever adopts, and nothing can have the database open while
// it is moved. EchoDatabase::open() refuses to create a fresh echo.db beside an unadopted
// tar.db, so a failed adoption fails closed instead of booting with default config. The caller
// defers adoption entirely while the plugin dir holds only the retired tar plugin (an OTA
// replaces the agent binary alone): the next start after echo.<ext> is installed adopts.
//
// Order is load-bearing: sidecars (-journal, -wal, -shm) move BEFORE the main file. An
// interrupted adoption therefore always looks like "tar.db present, echo.db absent" and resumes
// on the next boot, and echo.db can never be opened while its WAL still carries the old name.
//
// Accepted limit of that resume state: when tar.db is present, its own sidecar is absent and the
// echo.db sidecar exists, the helper takes the echo.db sidecar to be tar.db's own, already moved.
// It cannot tell that from a stale one: if an older agent is run against tar.db between the
// interruption and the next boot, writes, and cleanly checkpoints and deletes its WAL, the
// re-upgrade pairs the newer tar.db with the earlier echo.db WAL and replays it over the newer
// file. No cheap check separates the two (a checkpoint writes tar.db after the WAL's last frame,
// so an mtime or header comparison would refuse legitimate resumes), so the residual is accepted.
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
#include <string>
#include <system_error>

#include <spdlog/spdlog.h>

namespace yuzu::agent {

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

    if (echo_present && legacy_present) {
        spdlog::warn("Legacy {} exists beside {}: two independent databases. {} is used; the legacy "
                     "file and its sidecars are left untouched for the operator",
                     legacy.string(), echo_db.string(), echo_db.string());
        return {};
    }

    // No legacy main file: nothing to adopt. A stray legacy sidecar is left where it is, never
    // moved onto echo.db (see the header comment).
    if (!legacy_present) {
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

    // Sidecars first. A source that does not exist is already moved (or never was): success.
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
    spdlog::info("Adopted legacy {} as {}", legacy.string(), echo_db.string());
    return {};
}

} // namespace yuzu::agent
