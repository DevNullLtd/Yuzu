// Shared TarDatabase test helper for the tar suite (yuzu_tar_tests).
//
// WHY: TarDatabase::open() leaves SQLite at synchronous=FULL, so every commit
// fsyncs -- 17 per bare open() of a new database (measured with strace) and
// ~4.3k per suite run across ~180 scratch databases (strace count). That is
// cheap on a tmpfs-backed /tmp and costly on a real disk (Linux NVMe suite wall
// time ~3 s quiet -> ~1.2 s). The Windows tar suite timed out at its 90 s budget
// on dev CI run 37143292654; fsync cost is the inferred cause there, not a
// measured one. These databases are deleted at the end of the test, so
// durability buys nothing.
//
// USE open_tar_test_db() for any test that merely needs a populated store.
// Do NOT use it -- open with plain TarDatabase::open(path) instead -- for a test
// that exercises durability, crash recovery, file corruption, the open-time
// integrity check / quarantine, or WAL checkpoint behaviour: those must run the
// production synchronous=FULL path. test_tar_store.cpp pins that the default
// open reports synchronous=2 and the relaxed open reports 0.
#pragma once

#include "tar_db.hpp"

#include <expected>
#include <filesystem>
#include <string>

namespace yuzu::test {

inline std::expected<yuzu::tar::TarDatabase, std::string>
open_tar_test_db(const std::filesystem::path& path) {
    yuzu::tar::TarOpenOptions opts;
    opts.relaxed_durability_for_test = true;
    return yuzu::tar::TarDatabase::open(path, opts);
}

} // namespace yuzu::test
