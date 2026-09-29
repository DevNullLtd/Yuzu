/**
 * test_legacy_sqlite_probe.cpp — Unit tests for the shared fresh-start
 * detect-and-warn helper (`legacy_sqlite_probe.hpp`), introduced with
 * ADR-0061 (UpdateRegistry) and reused by the sibling PatchManager/
 * DirectorySync migrations. Pure SQLite + filesystem — no Postgres needed.
 */

#include "legacy_sqlite_probe.hpp"

#include "sqlite_raii.hpp"

#include "../test_helpers.hpp"
#include "../test_log_capture.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sqlite3.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <string>
#include <vector>

#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif

using yuzu::server::SqliteDb;
using yuzu::server::SqliteErrMsg;
using yuzu::server::legacy_sqlite_probe::harden_legacy_file_0600;
using yuzu::server::legacy_sqlite_probe::warn_if_legacy_rows;

TEST_CASE("legacy_sqlite_probe: silent when the legacy file does not exist",
          "[legacy_sqlite_probe]") {
    auto path = yuzu::test::unique_temp_path("yuzu_test_legacyprobe_nofile_");
    REQUIRE_FALSE(std::filesystem::exists(path));

    yuzu::test::LogCapture cap;
    warn_if_legacy_rows(path, "TestStore", {"widgets"});
    cap.stop();
    CHECK(cap.text().find("legacy") == std::string::npos);
}

TEST_CASE("legacy_sqlite_probe: silent when the probed table is absent",
          "[legacy_sqlite_probe]") {
    yuzu::test::TempDbFile legacy{"yuzu_test_legacyprobe_notable_"};
    {
        SqliteDb raw;
        REQUIRE(sqlite3_open(legacy.path.string().c_str(), raw.addr()) == SQLITE_OK);
        SqliteErrMsg err;
        REQUIRE(sqlite3_exec(raw.get(), "CREATE TABLE unrelated (x INTEGER);", nullptr, nullptr,
                             err.addr()) == SQLITE_OK);
    }

    yuzu::test::LogCapture cap;
    warn_if_legacy_rows(legacy.path, "TestStore", {"widgets"});
    cap.stop();
    CHECK(cap.text().find("legacy") == std::string::npos);
}

TEST_CASE("legacy_sqlite_probe: silent when the probed table is empty",
          "[legacy_sqlite_probe]") {
    yuzu::test::TempDbFile legacy{"yuzu_test_legacyprobe_empty_"};
    {
        SqliteDb raw;
        REQUIRE(sqlite3_open(legacy.path.string().c_str(), raw.addr()) == SQLITE_OK);
        SqliteErrMsg err;
        REQUIRE(sqlite3_exec(raw.get(), "CREATE TABLE widgets (id INTEGER PRIMARY KEY);", nullptr,
                             nullptr, err.addr()) == SQLITE_OK);
    }

    yuzu::test::LogCapture cap;
    warn_if_legacy_rows(legacy.path, "TestStore", {"widgets"});
    cap.stop();
    CHECK(cap.text().find("legacy") == std::string::npos);
}

TEST_CASE("legacy_sqlite_probe: warns with a row count when real rows exist",
          "[legacy_sqlite_probe]") {
    yuzu::test::TempDbFile legacy{"yuzu_test_legacyprobe_realdata_"};
    {
        SqliteDb raw;
        REQUIRE(sqlite3_open(legacy.path.string().c_str(), raw.addr()) == SQLITE_OK);
        SqliteErrMsg err;
        REQUIRE(sqlite3_exec(raw.get(),
                             "CREATE TABLE widgets (id INTEGER PRIMARY KEY); "
                             "INSERT INTO widgets VALUES (1),(2),(3);",
                             nullptr, nullptr, err.addr()) == SQLITE_OK);
    }

    yuzu::test::LogCapture cap;
    warn_if_legacy_rows(legacy.path, "TestStore", {"widgets"});
    cap.stop();
    const std::string text = cap.text();
    CHECK(text.find("TestStore") != std::string::npos);
    CHECK(text.find("widgets") != std::string::npos);
    CHECK(text.find("holds 3 row(s)") != std::string::npos);
    CHECK(text.find(legacy.path.string()) != std::string::npos);
}

TEST_CASE("legacy_sqlite_probe: multi-table store warns once per non-empty table, stays "
          "silent for empty/absent ones",
          "[legacy_sqlite_probe]") {
    yuzu::test::TempDbFile legacy{"yuzu_test_legacyprobe_multi_"};
    {
        SqliteDb raw;
        REQUIRE(sqlite3_open(legacy.path.string().c_str(), raw.addr()) == SQLITE_OK);
        SqliteErrMsg err;
        REQUIRE(sqlite3_exec(raw.get(),
                             "CREATE TABLE a (id INTEGER PRIMARY KEY); "
                             "CREATE TABLE b (id INTEGER PRIMARY KEY); "
                             "INSERT INTO a VALUES (1);", // b stays empty; c is never created
                             nullptr, nullptr, err.addr()) == SQLITE_OK);
    }

    yuzu::test::LogCapture cap;
    warn_if_legacy_rows(legacy.path, "TestStore", {"a", "b", "c"});
    cap.stop();
    const std::string text = cap.text();
    CHECK(text.find("table 'a'") != std::string::npos);
    CHECK(text.find("holds 1 row(s)") != std::string::npos);
    CHECK(text.find("table 'b'") == std::string::npos);
    CHECK(text.find("table 'c'") == std::string::npos);
}

TEST_CASE("legacy_sqlite_probe: warns defensively when the legacy file is corrupt",
          "[legacy_sqlite_probe]") {
    yuzu::test::TempDbFile legacy{"yuzu_test_legacyprobe_corrupt_"};
    {
        std::ofstream f(legacy.path, std::ios::binary);
        REQUIRE(f.is_open());
        f << "this is not a valid sqlite database file";
    }

    yuzu::test::LogCapture cap;
    warn_if_legacy_rows(legacy.path, "TestStore", {"widgets"});
    cap.stop();
    // Specific substring, not just "legacy" -- pins THIS branch ("could not be
    // read as a SQLite database") distinctly from the sibling "could not be
    // opened" and "could not be checked" warn branches (quality-engineer NICE,
    // adversarial review 2026-08-28: a bare "legacy" substring can't tell them
    // apart, so a future regression that fired the wrong branch would still
    // pass this assertion).
    CHECK(cap.text().find("could not be read as a SQLite database") != std::string::npos);
}

#ifndef _WIN32
// gov cpp-safety/architect/sre/quality-engineer (adversarial review, 2026-08-28,
// converged independently across 4 reviewers): regression test for the FIFO/
// non-regular-file startup-hang hazard this file's own is_regular_file() guard
// exists to close. Without the guard, std::filesystem::exists() would return
// true for a FIFO and sqlite3_open_v2(..., SQLITE_OPEN_READONLY, ...) would
// block indefinitely waiting for a writer that never arrives -- reproduced
// empirically by two independent adversarial-review models. Bounded via
// std::async + wait_for rather than calling the function directly on this
// thread: a REGRESSION back to exists() reports failure promptly (the
// REQUIRE below fires at the 3s deadline) rather than never reporting at
// all -- though on an actual hang, std::future's destructor still BLOCKS
// joining the wedged async thread during unwind, so the PROCESS itself
// doesn't exit fast; the external suite-level timeout (meson test /
// nightly.yml) is the real backstop against an indefinite wall-clock hang
// (security-guardian NICE, adversarial review 2026-08-28: an earlier
// version of this comment overclaimed a clean fast failure).
TEST_CASE("legacy_sqlite_probe: does not hang on a FIFO at the legacy path",
          "[legacy_sqlite_probe]") {
    auto path = yuzu::test::unique_temp_path("yuzu_test_legacyprobe_fifo_");
    REQUIRE(::mkfifo(path.string().c_str(), 0600) == 0);
    struct FifoCleanup {
        std::filesystem::path path;
        ~FifoCleanup() { ::unlink(path.string().c_str()); }
    } fifo_cleanup{path};

    yuzu::test::LogCapture cap;
    // No writer ever opens the other end of the FIFO -- exactly the
    // no-writer-arrives shape that makes SQLITE_OPEN_READONLY's open() block
    // forever on this platform when the is_regular_file() guard is bypassed.
    auto fut = std::async(std::launch::async, [&] {
        warn_if_legacy_rows(path, "TestStore", {"widgets"});
    });
    // Generous safety-net bound (matches test_subprocess_runner.cpp's FIFO
    // handshake precedent) -- the guarded call actually returns in low
    // milliseconds; a regressed implementation reports failure at this
    // deadline rather than never reporting (see the file header comment for
    // why the process itself can still block past this point on unwind).
    const auto status = fut.wait_for(std::chrono::seconds(3));
    cap.stop();
    REQUIRE(status == std::future_status::ready); // else: regressed to exists(), hung on open()
    // Silent, matching every other non-regular/absent path this helper treats
    // as "not this store's data" -- a FIFO is refused before any SQLite call.
    CHECK(cap.text().find("legacy") == std::string::npos);
}

// gov cpp-safety/unhappy-path (adversarial review, 2026-08-28): regression test
// for the permission-denied-on-the-CONTAINING-DIRECTORY case this file's
// is_regular_file() error_code branch exists to distinguish from "genuinely
// absent". Before this fix, a stat() failure on the parent directory (EACCES)
// and a genuinely-missing file both fell through to the same silent return --
// real operator-authored legacy rows behind a permission wall went undetected
// with no warning.
TEST_CASE("legacy_sqlite_probe: warns (does not silently skip) when the legacy path "
          "cannot be stat'd due to a permission-denied parent directory",
          "[legacy_sqlite_probe]") {
    if (::geteuid() == 0) {
        SKIP("root bypasses directory permissions; cannot make stat() fail");
    }

    auto dir = yuzu::test::unique_temp_path("yuzu_test_legacyprobe_denied_");
    REQUIRE(std::filesystem::create_directory(dir));
    // RAII: restore permissions before removal even if an assertion throws,
    // so a permission-locked temp dir never leaks onto a CI box that reuses
    // workspaces (test_tar_store.cpp's DirGuard precedent).
    struct DirGuard {
        std::filesystem::path dir;
        ~DirGuard() {
            std::error_code ec;
            std::filesystem::permissions(dir, std::filesystem::perms::owner_all,
                                         std::filesystem::perm_options::add, ec);
            std::filesystem::remove_all(dir, ec);
        }
    } dir_guard{dir};

    auto legacy_path = dir / "legacy.db";
    {
        SqliteDb raw;
        REQUIRE(sqlite3_open(legacy_path.string().c_str(), raw.addr()) == SQLITE_OK);
        SqliteErrMsg err;
        REQUIRE(sqlite3_exec(raw.get(),
                             "CREATE TABLE widgets (id INTEGER PRIMARY KEY); "
                             "INSERT INTO widgets VALUES (1);",
                             nullptr, nullptr, err.addr()) == SQLITE_OK);
    }
    // Strip execute (search) permission from the DIRECTORY -- not the file
    // itself -- so stat() on the file inside it fails with EACCES.
    std::error_code perm_ec;
    std::filesystem::permissions(dir, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::replace, perm_ec);
    REQUIRE_FALSE(perm_ec);

    yuzu::test::LogCapture cap;
    warn_if_legacy_rows(legacy_path, "TestStore", {"widgets"});
    cap.stop();
    const std::string text = cap.text();
    // Loud, not silent -- the whole point of the fix. Never claims a row
    // count (it couldn't read one); just flags "could not be checked".
    // "could not be checked" alone is NOT unique to this branch -- the
    // per-table SQLITE_BUSY/IOERR branch shares the same phrase (quality-
    // engineer NICE, adversarial review 2026-08-28) -- so also assert the
    // absence of that branch's distinguishing "table '" fragment to pin
    // THIS (whole-file stat() failure) branch specifically.
    CHECK(text.find("could not be checked") != std::string::npos);
    CHECK(text.find("table '") == std::string::npos);
}

// ── harden_legacy_file_0600 (#3623, generalized from WebhookStore's own inline
// 0600+sidecar block, PR #3563) ──────────────────────────────────────────────

TEST_CASE("legacy_sqlite_probe: harden_legacy_file_0600 restricts the main file and all three "
          "sidecars to owner-only",
          "[legacy_sqlite_probe]") {
    // Covers `-wal`/`-shm` (WAL mode) AND `-journal` (rollback-journal mode) -- a secret-bearing
    // store's legacy SQLite file could be left in either journal mode depending on how it was
    // last closed, and only WAL-mode sidecars were covered before this test (external PR review,
    // 2026-09-04).
    auto legacy_path = yuzu::test::unique_temp_path("yuzu_test_legacyprobe_harden_") += ".db";
    std::ofstream(legacy_path) << "dummy-content";
    std::vector<std::filesystem::path> sidecars;
    for (const char* suffix : {"-wal", "-shm", "-journal"}) {
        auto side = legacy_path;
        side += suffix;
        std::ofstream(side) << "dummy-sidecar-content";
        sidecars.push_back(side);
    }
    struct Cleanup {
        std::vector<std::filesystem::path> paths;
        ~Cleanup() {
            std::error_code ec;
            for (const auto& p : paths)
                std::filesystem::remove(p, ec);
        }
    } cleanup{{legacy_path, sidecars[0], sidecars[1], sidecars[2]}};

    // Group/world-readable to start, matching the unclean-shutdown-leftover
    // shape the real code path defends against.
    const auto wide_open = std::filesystem::perms::owner_read | std::filesystem::perms::owner_write |
                           std::filesystem::perms::group_read | std::filesystem::perms::others_read;
    for (const auto& p : {legacy_path, sidecars[0], sidecars[1], sidecars[2]})
        std::filesystem::permissions(p, wide_open, std::filesystem::perm_options::replace);

    harden_legacy_file_0600(legacy_path, "TestStore");

    const auto owner_only =
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write;
    for (const auto& p : {legacy_path, sidecars[0], sidecars[1], sidecars[2]}) {
        std::error_code st_ec;
        const auto perms = std::filesystem::status(p, st_ec).permissions();
        REQUIRE_FALSE(st_ec);
        CHECK((perms & std::filesystem::perms::mask) == owner_only);
    }
}

TEST_CASE("legacy_sqlite_probe: harden_legacy_file_0600 is a silent no-op when the legacy "
          "file and its sidecars are absent",
          "[legacy_sqlite_probe]") {
    auto path = yuzu::test::unique_temp_path("yuzu_test_legacyprobe_harden_absent_");
    REQUIRE_FALSE(std::filesystem::exists(path));

    yuzu::test::LogCapture cap;
    harden_legacy_file_0600(path, "TestStore"); // must not throw
    cap.stop();
    // Genuinely silent -- not just missing a since-removed literal prefix (this function's log
    // lines are now store_name-prefixed, like warn_if_legacy_rows', so a stale substring check
    // here would vacuously pass even if a warning HAD fired).
    CHECK(cap.text().empty());
}

TEST_CASE("legacy_sqlite_probe: harden_legacy_file_0600 hardens the resolved target when the "
          "legacy path is a symlink",
          "[legacy_sqlite_probe]") {
    // Superseded 2026-09-03 (adversarial review): an earlier revision REFUSED to touch a
    // symlinked path, which left the real secret-bearing target ungated even though
    // `warn_if_legacy_rows` follows the same symlink moments later and reads it. The fd-based
    // rewrite below resolves the symlink via `open()` (exactly like that later probe open does)
    // and hardens the resulting descriptor, so the real target ends up 0600 either way.
    auto target = yuzu::test::unique_temp_path("yuzu_test_legacyprobe_harden_symtarget_") += ".db";
    std::ofstream(target) << "dummy-content";
    auto link = yuzu::test::unique_temp_path("yuzu_test_legacyprobe_harden_symlink_") += ".db";
    REQUIRE(::symlink(target.string().c_str(), link.string().c_str()) == 0);
    struct Cleanup {
        std::filesystem::path target, link;
        ~Cleanup() {
            std::error_code ec;
            std::filesystem::remove(target, ec);
            std::filesystem::remove(link, ec);
        }
    } cleanup{target, link};

    const auto wide_open = std::filesystem::perms::owner_read | std::filesystem::perms::owner_write |
                           std::filesystem::perms::group_read | std::filesystem::perms::others_read;
    std::filesystem::permissions(target, wide_open, std::filesystem::perm_options::replace);

    harden_legacy_file_0600(link, "TestStore");

    const auto owner_only =
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write;
    std::error_code st_ec;
    const auto target_perms = std::filesystem::status(target, st_ec).permissions();
    REQUIRE_FALSE(st_ec);
    // Target hardened — resolved through the symlink, not left wide-open.
    CHECK((target_perms & std::filesystem::perms::mask) == owner_only);

    // The link itself is untouched by the chmod (fchmod acts on the target's inode, not the
    // link) and remains a symlink.
    std::error_code lstat_ec;
    const auto link_status = std::filesystem::symlink_status(link, lstat_ec);
    REQUIRE_FALSE(lstat_ec);
    CHECK(link_status.type() == std::filesystem::file_type::symlink);
}

TEST_CASE("legacy_sqlite_probe: harden_legacy_file_0600 cannot widen or redirect a chmod onto "
          "a file it does not own",
          "[legacy_sqlite_probe]") {
    // Pins the ownership-gate half of the security argument in this header's doc comment: a
    // symlink to a file this process does NOT own must fail the fchmod (EPERM, best-effort,
    // logged, boot proceeds) rather than ever changing that file's mode -- the property that
    // makes following the symlink (see the test above) safe against an attacker-planted link to
    // an arbitrary file. Skipped (not just "as root") wherever the ownership premise doesn't
    // hold -- root can chmod anything, but so can a UID-remapped/rootless-container euid that
    // happens to already own /etc/passwd -- either way the fchmod would SUCCEED, mutating a real
    // system file instead of demonstrating the gate. Both checked before touching anything.
    if (::geteuid() == 0)
        SKIP("running as root -- the ownership gate does not apply, nothing to assert");
    else {
        const std::filesystem::path root_owned = "/etc/passwd"; // world-readable, root-owned
        struct stat owner_check{};
        REQUIRE(::stat(root_owned.c_str(), &owner_check) == 0);
        if (owner_check.st_uid == ::geteuid())
            SKIP("this process already owns /etc/passwd -- the ownership gate does not apply "
                 "here, nothing to assert");

        std::error_code st_ec;
        const auto before = std::filesystem::status(root_owned, st_ec);
        REQUIRE_FALSE(st_ec);
        REQUIRE(before.type() == std::filesystem::file_type::regular);
        const auto before_perms = before.permissions() & std::filesystem::perms::mask;

        auto link = yuzu::test::unique_temp_path("yuzu_test_legacyprobe_harden_noowner_") += ".db";
        REQUIRE(::symlink(root_owned.c_str(), link.string().c_str()) == 0);
        struct Cleanup {
            std::filesystem::path link;
            ~Cleanup() {
                std::error_code ec;
                std::filesystem::remove(link, ec);
            }
        } cleanup{link};

        yuzu::test::LogCapture cap;
        harden_legacy_file_0600(link, "TestStore"); // must not throw, must not touch /etc/passwd's mode
        cap.stop();

        std::error_code after_ec;
        const auto after_perms =
            std::filesystem::status(root_owned, after_ec).permissions() & std::filesystem::perms::mask;
        REQUIRE_FALSE(after_ec);
        CHECK(after_perms == before_perms); // unchanged -- the fchmod failed closed
        CHECK(cap.text().find("could not set 0600") != std::string::npos);
        // Pins the store_name parameter's actual effect (not just that call sites compile with
        // it) -- a future edit reordering or dropping the format argument on any of the three
        // chmod_owner_only call sites would otherwise go undetected (governance Gate 3,
        // quality-engineer, 2026-09-04).
        CHECK(cap.text().find("TestStore") != std::string::npos);
    }
}

TEST_CASE("legacy_sqlite_probe: harden_legacy_file_0600 leaves a non-regular path (a FIFO) "
          "untouched without blocking",
          "[legacy_sqlite_probe]") {
    // Guards the O_NONBLOCK choice: a plain open() on a FIFO with no writer blocks
    // indefinitely, the same hazard warn_if_legacy_rows avoids via is_regular_file(). Wrapped in
    // the same async+wait_for bound as the sibling FIFO test above (rather than calling
    // synchronously) so a regression here fails this test with a clear message instead of
    // hanging the whole suite -- see that test's file-header comment for why the process itself
    // can still block past this bound on unwind even so.
    auto fifo_path = yuzu::test::unique_temp_path("yuzu_test_legacyprobe_harden_fifo_");
    REQUIRE(::mkfifo(fifo_path.string().c_str(), 0600) == 0);
    struct Cleanup {
        std::filesystem::path path;
        ~Cleanup() {
            std::error_code ec;
            std::filesystem::remove(path, ec);
        }
    } cleanup{fifo_path};

    auto fut =
        std::async(std::launch::async, [&] { harden_legacy_file_0600(fifo_path, "TestStore"); });
    const auto status = fut.wait_for(std::chrono::seconds(3));
    REQUIRE(status == std::future_status::ready); // else: regressed off O_NONBLOCK, hung on open()
}
#endif // _WIN32
