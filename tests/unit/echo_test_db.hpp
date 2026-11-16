// Fast fresh-database opens for the echo unit tests.
//
// A fresh `EchoDatabase::open` walks the whole schema ladder (v2 to v10), one committed write per
// step, about 25 fsyncs in all. The suite opens ~455 databases, so on a disk with slow fsync (the
// shared Windows CI box) the run time is the fsync count times the commit latency: 85 s when the
// disk is quiet, past the 180 s meson timeout when it is not (#7135, #7872).
//
// `open_echo_db` builds ONE migrated database per process, closes it (which folds the WAL into the
// main file), and copies that file to each caller's path before opening. The open then finds a
// current-version database and skips the ladder. The copy is a file copy with no fsync of its own.
//
// Use it ONLY where the test wants "a database in the state a fresh open leaves". A test that is
// about the open itself or the ladder (an upgrade from an older version, a corrupt or colliding
// file, the open's log lines, a seeded legacy table) must keep calling `EchoDatabase::open` on a
// path it prepared.
#pragma once

#include "echo_db.hpp"
#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <mutex>
#include <system_error>

namespace yuzu::test {

namespace detail {

// The per-process migrated template. Built on first use, removed at process exit. An empty path
// means the build failed, and every caller then falls back to a plain fresh open.
struct EchoDbTemplate {
    std::filesystem::path path;

    EchoDbTemplate() {
        auto candidate = unique_temp_path("yuzu_test_echo_template_");
        {
            auto opened = yuzu::echo::EchoDatabase::open(candidate);
            if (!opened)
                return;
            // Fold the WAL into the main file explicitly. Do not lean on the close: the
            // read-only query connection closes last, and once it has run a statement the WAL is
            // left behind, so a copy of the main file alone would be missing its tables.
            if (opened->checkpoint(yuzu::echo::CheckpointMode::kTruncate) !=
                yuzu::echo::CheckpointResult::kOk)
                return;
        }
        std::error_code ec;
        const auto wal = std::filesystem::path{candidate.string() + "-wal"};
        if (std::filesystem::exists(wal, ec) && std::filesystem::file_size(wal, ec) != 0)
            return; // a non-empty WAL would not travel with the copy
        path = std::move(candidate);
    }

    ~EchoDbTemplate() {
        if (path.empty())
            return;
        std::error_code ec;
        std::filesystem::remove(path, ec);
        for (const char* suffix : {"-wal", "-shm", "-journal"})
            std::filesystem::remove(std::filesystem::path{path.string() + suffix}, ec);
    }

    EchoDbTemplate(const EchoDbTemplate&) = delete;
    EchoDbTemplate& operator=(const EchoDbTemplate&) = delete;
};

inline const EchoDbTemplate& echo_db_template() {
    static const EchoDbTemplate t;
    return t;
}

} // namespace detail

/// Copy the migrated template to `dest` when `dest` does not exist yet. Returns true when the copy
/// was made. A failure leaves `dest` absent, so the open that follows is an ordinary fresh one.
inline bool seed_echo_db_from_template(const std::filesystem::path& dest) {
    const auto& tpl = detail::echo_db_template();
    std::error_code ec;
    if (tpl.path.empty() || std::filesystem::exists(dest, ec))
        return false;
    ec.clear();
    if (!std::filesystem::copy_file(tpl.path, dest, std::filesystem::copy_options::none, ec)) {
        std::filesystem::remove(dest, ec);
        return false;
    }
    return true;
}

/// `EchoDatabase::open(path)` on a database that starts at the current schema version, with
/// `synchronous=OFF` on the write connection. The pragma is per connection and never persisted,
/// so it changes nothing about the file or the shipped binary; the fold tests already use it.
/// Do not use this helper for a test that asserts durability or crash behaviour.
inline auto open_echo_db(const std::filesystem::path& path) {
    (void)seed_echo_db_from_template(path);
    auto opened = yuzu::echo::EchoDatabase::open(path);
    if (opened)
        REQUIRE(opened->execute_sql("PRAGMA synchronous=OFF"));
    return opened;
}

} // namespace yuzu::test
