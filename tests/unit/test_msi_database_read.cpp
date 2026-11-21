/**
 * test_msi_database_read.cpp -- agent-core's bounded, read-only Property-table read of one
 * cached Windows Installer package (agents/core/src/msi_database_read.cpp), SAM-46.
 *
 * Two parts:
 *   - Every OS: the single-flight slot protocol. The seam is the overload that takes a
 *     caller-owned slot, so the test holds the slot itself and needs no genuinely hung read.
 *   - Windows only: the read through the REAL Installer API (a corrupt file, a missing file,
 *     a real cached package read while this test holds a no-reparse handle on it, a zero
 *     deadline). The Windows body is an empty TU elsewhere.
 *
 * TEST-EFFICIENCY JUSTIFICATION (a test whose runtime depends on the file system): the Windows
 * cases open at most a handful of files and read at most 64 packages' Property tables in the
 * one cache-scan case, each a bounded local read; the case stops at the first package whose
 * ProductCode it can read. Nothing here waits on a timer: a worker abandoned at a zero deadline
 * is waited for with SingleFlightSlot::wait_free(), an atomic wait.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/msi_database_read.hpp>

#include <chrono>
#include <string>

namespace msi = yuzu::agent::msi;
using std::chrono::milliseconds;

TEST_CASE("msi database read: a held slot answers Busy and the slot is left as it was",
          "[msi_packages][msi_database_read]") {
    // static: a worker the slot was handed to must never outlive it (none is started here)
    static msi::SingleFlightSlot slot;
    REQUIRE(slot.try_acquire());
    CHECK_FALSE(slot.try_acquire()); // one in flight at a time

    const auto r = msi::read_property_table(slot, "C:\\WINDOWS\\Installer\\x.msi", milliseconds{5000});
    CHECK(r.status == msi::ReadStatus::Busy);
    CHECK(r.elapsed == milliseconds{0}); // returned without waiting on anything
    CHECK(slot.in_flight());             // a Busy answer neither takes nor frees the slot

    slot.release();
    CHECK_FALSE(slot.in_flight());
}

TEST_CASE("msi database read: the slot is free again once a read has returned",
          "[msi_packages][msi_database_read]") {
    static msi::SingleFlightSlot slot;
    // A path that does not exist: on Windows the open fails, elsewhere the API is unavailable;
    // either way the answer is Completed (inside a generous deadline) and the worker has released
    // the slot BEFORE it published the answer, so it is free by the time the caller returns.
    const auto r = msi::read_property_table(slot, "C:\\WINDOWS\\Installer\\yuzu_test_none.msi",
                                            milliseconds{30000});
    REQUIRE(r.status == msi::ReadStatus::Completed);
    CHECK(r.outcome.kind != msi::Outcome::Kind::Ok);
    CHECK_FALSE(slot.in_flight());
    REQUIRE(slot.try_acquire()); // not Busy
    slot.release();
}

#ifndef _WIN32

TEST_CASE("msi database read: off Windows the API is unavailable", "[msi_packages][msi_database_read]") {
    // The exported, process-wide overload the plugin calls: nothing else takes that slot off
    // Windows, so it cannot be Busy, and the worker must have released it by the time it returns.
    const auto r = msi::read_property_table("/nowhere.msi", milliseconds{30000});
    REQUIRE(r.status == msi::ReadStatus::Completed);
    CHECK(r.outcome.kind == msi::Outcome::Kind::ApiUnavailable);
    CHECK(r.outcome.props.product_code.empty());
    CHECK_FALSE(msi::read_in_flight());
}

#else // _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <win_no_reparse_open.hpp> // yuzu::win::open_file_no_reparse

#include "test_helpers.hpp"

#include <cctype>
#include <filesystem>
#include <system_error>

namespace fs = std::filesystem;

#ifndef YUZU_TEST_FIXTURE_DIR
#define YUZU_TEST_FIXTURE_DIR "tests/unit/fixtures"
#endif

namespace {

fs::path fixture_package() {
    return fs::path{YUZU_TEST_FIXTURE_DIR} / "software-estate" / "msi_packages" / "windows" /
           "corrupt-package.msi";
}

} // namespace

TEST_CASE("msi database read: a file that is not a database fails to open, inside the deadline",
          "[msi_packages][msi_database_read][windows_actions]") {
    yuzu::test::TempDir dir{"yuzu_test_msi_read_"};
    std::error_code ec;
    fs::create_directories(dir.path, ec);
    REQUIRE_FALSE(ec);
    const auto copy = dir.path / "corrupt.msi";
    fs::copy_file(fixture_package(), copy, ec);
    REQUIRE_FALSE(ec);

    static msi::SingleFlightSlot slot;
    const auto r = msi::read_property_table(slot, copy.string(), milliseconds{30000});
    REQUIRE(r.status == msi::ReadStatus::Completed);
    CHECK(r.outcome.kind == msi::Outcome::Kind::OpenFailed);
    CHECK(r.outcome.rc != 0);
    CHECK(r.elapsed < milliseconds{30000});
    CHECK(r.outcome.props.product_code.empty());
    CHECK_FALSE(slot.in_flight());
}

TEST_CASE("msi database read: a path that does not exist fails to open",
          "[msi_packages][msi_database_read][windows_actions]") {
    yuzu::test::TempDir dir{"yuzu_test_msi_read_"}; // salted per process; never created
    static msi::SingleFlightSlot slot;
    const auto r = msi::read_property_table(slot, (dir.path / "absent.msi").string(), milliseconds{30000});
    REQUIRE(r.status == msi::ReadStatus::Completed);
    CHECK(r.outcome.kind == msi::Outcome::Kind::OpenFailed);
    CHECK(r.outcome.rc != 0);
}

TEST_CASE("msi database read: a real cached package reads while a no-reparse handle is held on it",
          "[msi_packages][msi_database_read][windows_actions]") {
    wchar_t windir[MAX_PATH]{};
    const UINT n = GetSystemWindowsDirectoryW(windir, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        SKIP("the system Windows directory could not be read");
    const fs::path cache = fs::path{windir} / "Installer";

    std::error_code ec;
    fs::directory_iterator it{cache, ec};
    if (ec)
        SKIP("the Installer cache cannot be listed by this identity (" << ec.message() << ")");

    static msi::SingleFlightSlot slot;
    int tried = 0;
    bool exercised = false;
    for (const fs::directory_iterator end; it != end && tried < 64 && !exercised; it.increment(ec)) {
        if (ec)
            break;
        const auto& p = it->path();
        std::string ext = p.extension().string();
        for (char& c : ext)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (ext != ".msi")
            continue;
        ++tried;
        // A candidate is a package this identity reads Ok with no handle held; one it cannot
        // open at all is skipped here, so a failure under the handle below is the handle's.
        const auto bare = msi::read_property_table(slot, p.string(), milliseconds{5000});
        if (bare.status != msi::ReadStatus::Completed || bare.outcome.kind != msi::Outcome::Kind::Ok)
            continue;
        exercised = true;
        INFO(p.string());
        // The handle the plugin holds while the database is read: share read only, so the API's
        // own read-only open must be share-compatible with it.
        auto held = yuzu::win::open_file_no_reparse(p.wstring(), FILE_SHARE_READ);
        REQUIRE(held.status == yuzu::win::NoReparseOpen::ok);
        const auto r = msi::read_property_table(slot, p.string(), milliseconds{5000});
        REQUIRE(r.status == msi::ReadStatus::Completed);
        REQUIRE(r.outcome.kind == msi::Outcome::Kind::Ok);
        const auto& code = r.outcome.props.product_code;
        REQUIRE(code.size() == 38);
        CHECK(code.front() == '{');
        CHECK(code.back() == '}');
        CHECK(code == bare.outcome.props.product_code);
    }
    if (!exercised)
        SKIP("the Installer cache holds no package this identity can read without a held handle");
}

TEST_CASE("msi database read: a zero deadline never blocks and the slot frees when the worker returns",
          "[msi_packages][msi_database_read][windows_actions]") {
    yuzu::test::TempDir dir{"yuzu_test_msi_read_"};
    std::error_code ec;
    fs::create_directories(dir.path, ec);
    REQUIRE_FALSE(ec);
    const auto copy = dir.path / "corrupt.msi";
    fs::copy_file(fixture_package(), copy, ec);
    REQUIRE_FALSE(ec);

    static msi::SingleFlightSlot slot;
    const auto r = msi::read_property_table(slot, copy.string(), milliseconds{0});
    CHECK((r.status == msi::ReadStatus::TimedOut || r.status == msi::ReadStatus::Completed));
    // A TimedOut worker still holds the slot and releases it when it returns; wait for that
    // (an atomic wait, not a poll), then the next read is not Busy.
    slot.wait_free();
    const auto again = msi::read_property_table(slot, copy.string(), milliseconds{30000});
    CHECK(again.status == msi::ReadStatus::Completed);
    CHECK(again.outcome.kind == msi::Outcome::Kind::OpenFailed);
    slot.wait_free();
}

#endif // _WIN32
