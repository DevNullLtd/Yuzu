/**
 * test_posix_dir_walk.cpp — tests for the shared capped directory-walk
 * primitive (agents/shared/posix_dir_walk.hpp), extracted during PR #4154's
 * round-8 remediation so the correct cap/error-detection logic exists in
 * exactly one place instead of five hand-rolled copies across
 * autoruns_linux.cpp/autoruns_macos.cpp.
 *
 * The cap/truncation/clean-end shape is pinned against real `opendir`/
 * `readdir` over real temp directories -- no fakes. A genuine mid-scan
 * `readdir()` I/O error isn't reliably reproducible from userspace without
 * a filesystem-specific or libc-buffering-dependent trick (closing the
 * underlying fd or removing the directory mid-scan both have unpredictable,
 * implementation-dependent effects on whether the NEXT `readdir()` call
 * actually fails or just serves already-buffered entries) -- so issue #4183
 * closed that gap by giving `walk_dir_capped` an injectable `readdir_fn`
 * seam (production call sites are unaffected; the seam is only ever
 * supplied here) and the two `enumeration_error` paths below (the main loop
 * and the cap-boundary lookahead) exercise that seam directly instead of
 * relying on an unreliable real fault.
 */
#if !defined(_WIN32)

#include <catch2/catch_test_macros.hpp>

#include "test_helpers.hpp"

#include <posix_dir_walk.hpp>

#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

/// RAII owner for a POSIX DIR* opened against a real directory -- this test
/// file's own small helper, not a claim on any production ownership type.
struct TestDirHandle {
    DIR* d;
    explicit TestDirHandle(const fs::path& path) : d(::opendir(path.c_str())) {}
    ~TestDirHandle() {
        if (d) ::closedir(d);
    }
    TestDirHandle(const TestDirHandle&) = delete;
    TestDirHandle& operator=(const TestDirHandle&) = delete;
};

void touch(const fs::path& p) {
    std::ofstream f(p);
    f << "x";
}

/// A stateful, injectable readdir() replacement for #4183's fault-injection
/// tests: returns one synthetic `dirent` per name in `names`, in order, then
/// -- once `names` is exhausted or `fail_at` (an index into `names`, -1 =
/// never) is reached -- returns nullptr with `errno` set to `errno_value`,
/// distinct from the "clean end of directory" nullptr-with-errno-0 case.
/// Ignores the `DIR*` argument entirely (callers pass `nullptr` for it).
struct FakeReadDir {
    std::vector<std::string> names;
    int fail_at = -1;
    int errno_value = EIO;
    std::size_t idx = 0;
    struct dirent buf {};

    struct dirent* operator()(DIR*) {
        if (fail_at >= 0 && idx == static_cast<std::size_t>(fail_at)) {
            errno = errno_value;
            return nullptr;
        }
        if (idx >= names.size()) {
            errno = 0;
            return nullptr;
        }
        std::strncpy(buf.d_name, names[idx].c_str(), sizeof(buf.d_name) - 1);
        buf.d_name[sizeof(buf.d_name) - 1] = '\0';
        ++idx;
        return &buf;
    }
};

} // namespace

TEST_CASE("posix_dir_walk: walk_dir_capped on a genuinely empty directory reports "
          "clean, not truncated, no error",
          "[posix_dir_walk]") {
    yuzu::test::TempDir dir("yuzu_test_posix_dir_walk_empty_");
    fs::create_directories(dir.path);
    TestDirHandle handle(dir.path);
    REQUIRE(handle.d != nullptr);

    int count = 0;
    const auto result = yuzu::shared::walk_dir_capped(
        handle.d, 10, [&](const struct dirent*) {
            ++count;
            return true;
        });

    CHECK(count == 0);
    CHECK_FALSE(result.truncated);
    CHECK_FALSE(result.enumeration_error);
}

TEST_CASE("posix_dir_walk: walk_dir_capped with fewer real entries than the cap reports "
          "clean, not truncated",
          "[posix_dir_walk]") {
    yuzu::test::TempDir dir("yuzu_test_posix_dir_walk_under_cap_");
    fs::create_directories(dir.path);
    touch(dir.path / "a");
    touch(dir.path / "b");
    TestDirHandle handle(dir.path);
    REQUIRE(handle.d != nullptr);

    int count = 0;
    const auto result = yuzu::shared::walk_dir_capped(
        handle.d, 10, [&](const struct dirent*) {
            ++count;
            return true;
        });

    CHECK(count == 2);
    CHECK_FALSE(result.truncated);
    CHECK_FALSE(result.enumeration_error);
}

TEST_CASE("posix_dir_walk: walk_dir_capped with more real entries than the cap reports "
          "truncated, never an error "
          "(RECONSTRUCTION: pins PR #4154 round 8's blocker -- the cap-boundary "
          "lookahead call itself is now checked, not just the main loop's own "
          "readdir() calls)",
          "[posix_dir_walk]") {
    yuzu::test::TempDir dir("yuzu_test_posix_dir_walk_over_cap_");
    fs::create_directories(dir.path);
    for (int i = 0; i < 5; ++i) touch(dir.path / ("f" + std::to_string(i)));
    TestDirHandle handle(dir.path);
    REQUIRE(handle.d != nullptr);

    int count = 0;
    const auto result = yuzu::shared::walk_dir_capped(
        handle.d, 3, [&](const struct dirent*) {
            ++count;
            return true;
        });

    CHECK(count == 3);
    CHECK(result.truncated);
    CHECK_FALSE(result.enumeration_error);
}

TEST_CASE("posix_dir_walk: a directory with EXACTLY the cap's worth of entries is not "
          "reported truncated",
          "[posix_dir_walk]") {
    yuzu::test::TempDir dir("yuzu_test_posix_dir_walk_exact_cap_");
    fs::create_directories(dir.path);
    for (int i = 0; i < 4; ++i) touch(dir.path / ("f" + std::to_string(i)));
    TestDirHandle handle(dir.path);
    REQUIRE(handle.d != nullptr);

    int count = 0;
    const auto result = yuzu::shared::walk_dir_capped(
        handle.d, 4, [&](const struct dirent*) {
            ++count;
            return true;
        });

    CHECK(count == 4);
    CHECK_FALSE(result.truncated);
    CHECK_FALSE(result.enumeration_error);
}

TEST_CASE("posix_dir_walk: on_entry returning false stops the walk early without it "
          "counting as truncation -- the caller decided it has enough, not that data "
          "was missed",
          "[posix_dir_walk]") {
    yuzu::test::TempDir dir("yuzu_test_posix_dir_walk_early_stop_");
    fs::create_directories(dir.path);
    for (int i = 0; i < 5; ++i) touch(dir.path / ("f" + std::to_string(i)));
    TestDirHandle handle(dir.path);
    REQUIRE(handle.d != nullptr);

    int count = 0;
    const auto result = yuzu::shared::walk_dir_capped(
        handle.d, 10, [&](const struct dirent*) {
            ++count;
            return count < 2; // stop right after the 2nd real entry
        });

    CHECK(count == 2);
    CHECK_FALSE(result.truncated);
    CHECK_FALSE(result.enumeration_error);
}

TEST_CASE("posix_dir_walk: a main-loop readdir() I/O error reports enumeration_error, "
          "never truncated -- #4183 fault-injection",
          "[posix_dir_walk]") {
    FakeReadDir fake;
    fake.names = {"f0", "f1"};
    fake.fail_at = 2; // fails on the 3rd call, after 2 real entries returned

    int count = 0;
    const auto result = yuzu::shared::walk_dir_capped(
        nullptr, 10, [&](const struct dirent*) {
            ++count;
            return true;
        },
        fake);

    CHECK(count == 2);
    CHECK(result.enumeration_error);
    CHECK_FALSE(result.truncated);
}

TEST_CASE("posix_dir_walk: a cap-boundary lookahead readdir() I/O error reports "
          "enumeration_error, never truncated -- #4183 fault-injection, pins the "
          "PR #4154 round-8 finding this primitive exists to fix",
          "[posix_dir_walk]") {
    FakeReadDir fake;
    fake.names = {"f0", "f1", "f2"}; // exactly `cap` real entries
    fake.fail_at = 3;                // the lookahead call itself fails

    int count = 0;
    const auto result = yuzu::shared::walk_dir_capped(
        nullptr, 3, [&](const struct dirent*) {
            ++count;
            return true;
        },
        fake);

    CHECK(count == 3);
    CHECK(result.enumeration_error);
    CHECK_FALSE(result.truncated);
}

TEST_CASE("posix_dir_walk: a cap-boundary lookahead that finds only `.`/`..` before "
          "clean end-of-directory is NOT reported truncated",
          "[posix_dir_walk]") {
    FakeReadDir fake;
    // 3 real entries fill the cap; the lookahead then sees both dot entries
    // and clean EOD -- no real entry was left unread.
    fake.names = {"f0", "f1", "f2", "..", "."};

    int count = 0;
    const auto result = yuzu::shared::walk_dir_capped(
        nullptr, 3, [&](const struct dirent*) {
            ++count;
            return true;
        },
        fake);

    CHECK(count == 3);
    CHECK_FALSE(result.truncated);
    CHECK_FALSE(result.enumeration_error);
}

TEST_CASE("posix_dir_walk: a cap-boundary lookahead that skips a dot entry and then "
          "finds a real one IS reported truncated",
          "[posix_dir_walk]") {
    FakeReadDir fake;
    fake.names = {"f0", "f1", "f2", ".", "f3"};

    int count = 0;
    const auto result = yuzu::shared::walk_dir_capped(
        nullptr, 3, [&](const struct dirent*) {
            ++count;
            return true;
        },
        fake);

    CHECK(count == 3);
    CHECK(result.truncated);
    CHECK_FALSE(result.enumeration_error);
}

#endif // !defined(_WIN32)
