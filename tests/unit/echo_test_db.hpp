// Fast fresh-database opens for the echo unit tests.
//
// A fresh `EchoDatabase::open` walks the whole schema ladder (v2 to v10), one committed write per
// step, about 25 fsyncs in all. The suite opens about 470 databases, so on a disk with slow fsync (the
// shared Windows CI box) the run time is the fsync count times the commit latency: about 50 to
// 85 s when the disk is quiet (51 s on a CI runner and 82 s on a standalone Windows host, see
// tests/meson.build), past the 180 s meson timeout when it is not (#7135, #7872).
//
// `open_echo_db` builds ONE migrated database per process, checkpoints it with a TRUNCATE
// checkpoint (closing alone does not fold the WAL, see the constructor) and closes it, then copies
// that file to each caller's path before opening. The open then finds a current-version database
// and skips the ladder. The copy is a file copy with no fsync of its own. The write connection also
// gets `PRAGMA synchronous=OFF` (per connection, never persisted).
//
// Use it ONLY where the test wants "a database in the state a fresh open leaves". A test that is
// about the open itself or the ladder (a fresh open's own end state, an upgrade from an older
// version, a corrupt or colliding file, the open's log lines, a seeded legacy table) or about
// durability or crash behaviour must keep calling `EchoDatabase::open` on a path it prepared.
//
// Call it from the test's own thread: it contains a Catch2 REQUIRE, which is not safe off the thread
// that runs the test case.
//
// For the yuzu_echo_tests executable only. That executable links Catch2WithMain, so the template's
// static destructor runs at exit. An executable built on test_runner_main.cpp leaves through
// hard_exit() on Windows and macOS, which skips static destructors and would strand the template
// file on every run.
#pragma once

#include "echo_db.hpp"
#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdio>
#include <expected>
#include <filesystem>
#include <string>
#include <system_error>

namespace yuzu::test {

namespace detail {

// The per-process migrated template. Built on first use. `file` owns the candidate path from the
// moment it is chosen, so EVERY outcome, including each early return below, removes the main file
// and its -wal/-shm/-journal companions at process exit. `ready` is true only when the template is
// complete and safe to copy; otherwise every caller falls back to a plain fresh open, and the
// reason is printed so a run that lost its speed-up is not silent.
struct EchoDbTemplate {
    TempDbFile file{"yuzu_test_echo_template_"};
    bool ready = false;

    EchoDbTemplate() {
        {
            auto opened = yuzu::echo::EchoDatabase::open(file.path);
            if (!opened) {
                refuse("open failed: " + opened.error());
                return;
            }
            // Fold the WAL into the main file explicitly. Do not lean on the close: the
            // read-only query connection closes last, and once it has run a statement the WAL is
            // left behind, so a copy of the main file alone would be missing its tables.
            if (opened->checkpoint(yuzu::echo::CheckpointMode::kTruncate) !=
                yuzu::echo::CheckpointResult::kOk) {
                refuse("TRUNCATE checkpoint did not complete");
                return;
            }
        }
        // One error-checked size read. A missing -wal is an empty log; any other error, or a
        // non-empty log, would not travel with the copy.
        std::error_code ec;
        const auto wal_bytes =
            std::filesystem::file_size(std::filesystem::path{file.path.string() + "-wal"}, ec);
        if (ec && ec != std::errc::no_such_file_or_directory) {
            refuse("could not read the -wal size: " + ec.message());
            return;
        }
        if (!ec && wal_bytes != 0) {
            refuse("a non-empty -wal remains after the checkpoint");
            return;
        }
        ready = true;
    }

    EchoDbTemplate(const EchoDbTemplate&) = delete;
    EchoDbTemplate& operator=(const EchoDbTemplate&) = delete;

  private:
    void refuse(const std::string& why) const {
        std::fprintf(stderr,
                     "echo_test_db: migrated template unavailable (%s); echo fixtures fall back "
                     "to a plain fresh open (correct, slower)\n",
                     why.c_str());
    }
};

inline const EchoDbTemplate& echo_db_template() {
    static const EchoDbTemplate t;
    return t;
}

} // namespace detail

/// Copy the migrated template to `dest` when `dest` does not exist yet. Returns true when the copy
/// was made. The copy is written to `<dest>.tmp` and renamed into place, so `dest` is never a
/// partial file: a failure leaves `dest` absent and the open that follows is an ordinary fresh one.
/// A `dest` that already existed is never touched or removed (checked up front, not race-proof).
inline bool seed_echo_db_from_template(const std::filesystem::path& dest) {
    const auto& tpl = detail::echo_db_template();
    std::error_code ec;
    if (!tpl.ready || std::filesystem::exists(dest, ec))
        return false;
    const std::filesystem::path staging{dest.string() + ".tmp"};
    ec.clear();
    if (!std::filesystem::copy_file(tpl.file.path, staging, std::filesystem::copy_options::none,
                                    ec)) {
        if (ec != std::errc::file_exists) // not ours to remove if someone else made it meanwhile
            std::filesystem::remove(staging, ec);
        return false;
    }
    // rename() replaces an existing destination on POSIX and on Windows. `dest` was checked absent
    // above and the path is per-process salted, so nothing else creates it; either way `dest` is
    // complete or absent, never partial.
    std::filesystem::rename(staging, dest, ec);
    if (ec) {
        std::filesystem::remove(staging, ec);
        return false;
    }
    return true;
}

/// `EchoDatabase::open(path)` on a database that starts at the current schema version, with
/// `synchronous=OFF` on the write connection. The pragma is per connection and never persisted,
/// so it changes nothing about the file or the shipped binary; the fold tests already use it.
inline std::expected<yuzu::echo::EchoDatabase, std::string>
open_echo_db(const std::filesystem::path& path) {
    (void)seed_echo_db_from_template(path);
    auto opened = yuzu::echo::EchoDatabase::open(path);
    if (opened)
        REQUIRE(opened->execute_sql("PRAGMA synchronous=OFF"));
    return opened;
}

} // namespace yuzu::test
