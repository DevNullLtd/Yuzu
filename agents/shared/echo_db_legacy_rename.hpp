// echo_db_legacy_rename.hpp -- adopt a pre-rename tar.db as echo.db.
//
// Upgrade-window helper (removed with the other legacy-name shims). Before the Echo rename the
// activity-record database lived at <data_dir>/tar.db; it now lives at <data_dir>/echo.db. The
// file keeps its DACL / mode and content, so adoption is a rename, nothing else.
//
// ONE caller: agent core at boot (agents/core/src/agent.cpp), after the KV store opens and
// before any plugin is loaded or initialised. That placement is the exclusion: no process-wide
// lock exists across plugin dylibs, so no plugin ever adopts, and nothing can have the database
// open while it is moved. EchoDatabase::open() refuses to create a fresh echo.db beside an
// unadopted tar.db, so a failed adoption fails closed instead of booting with default config.
//
// Order is load-bearing: sidecars (-journal, -wal, -shm) move BEFORE the main file. An
// interrupted adoption therefore always looks like "tar.db present, echo.db absent" and resumes
// on the next boot, and echo.db can never be opened while its WAL still carries the old name.
//
// If both main files exist they are two independent databases (an agent downgraded after the
// rename, then upgraded again). Nothing is touched: echo.db wins, tar.db and its sidecars are
// left for the operator, and one warning names them. Old tar.db.corrupt-* quarantine files are
// never touched.
#pragma once

#include <spdlog/spdlog.h>

#include <expected>
#include <filesystem>
#include <format>
#include <string>
#include <system_error>

namespace yuzu::shared {

[[nodiscard]] inline std::expected<void, std::string>
adopt_legacy_echo_db(const std::filesystem::path& echo_db) {
    namespace fs = std::filesystem;
    constexpr const char* kSidecars[] = {"-journal", "-wal", "-shm"};
    const fs::path legacy = echo_db.parent_path() / "tar.db";
    const auto with = [](const fs::path& base, const char* suffix) {
        return fs::path{base.string() + suffix};
    };

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

    // Sidecars first. A source that does not exist is already moved (or never was): success.
    for (const char* suffix : kSidecars) {
        const fs::path from = with(legacy, suffix);
        const fs::path to = with(echo_db, suffix);
        if (!fs::exists(from, ec)) {
            if (ec)
                return std::unexpected(
                    std::format("cannot stat {}: {}", from.string(), ec.message()));
            continue;
        }
        // Never overwrite: a sidecar already at the echo name belongs to a live echo.db (an
        // overwritten -wal would lose committed rows). Leave the stale one for the operator.
        if (fs::exists(to, ec)) {
            spdlog::warn("Legacy {} left in place: {} already exists", from.string(), to.string());
            continue;
        }
        fs::rename(from, to, ec);
        if (ec)
            return std::unexpected(std::format("cannot move {} to {}: {}", from.string(),
                                               to.string(), ec.message()));
        spdlog::info("Adopted legacy {} as {}", from.string(), to.string());
    }

    if (legacy_present) {
        fs::rename(legacy, echo_db, ec);
        if (ec)
            return std::unexpected(std::format("cannot move {} to {}: {}", legacy.string(),
                                               echo_db.string(), ec.message()));
        spdlog::info("Adopted legacy {} as {}", legacy.string(), echo_db.string());
    }
    return {};
}

} // namespace yuzu::shared
