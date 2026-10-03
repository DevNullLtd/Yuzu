/**
 * test_execution_artifacts_scratch_sweep.cpp — A1 (#4390): coverage for
 * execution_artifacts_scratch_sweep.hpp's selection policy (every OS) and
 * execution_artifacts_scratch_sweep_win.cpp's confined_fs-based Windows
 * shell (Windows only, real filesystem, real junctions -- test_confined_fs_
 * win.cpp's own precedent for why: mtimes are set explicitly via SetFileTime,
 * never sleeps).
 *
 * UNGUARDED TU: the portable cases at the top of this file run on every OS;
 * everything below the `#if defined(_WIN32)` exercises the real Windows
 * shell and, for the two end-to-end cases, the real compiled
 * execution_artifacts plugin via the same PluginHandle/LocalDispatcher
 * harness test_execution_artifacts_win_local.cpp already uses.
 */
#include "execution_artifacts_scratch_sweep.hpp"

#include <catch2/catch_test_macros.hpp>

#include <wall_clock_step.hpp> // yuzu::shared::ClockStepGuard (#4503)

#include "test_helpers.hpp" // yuzu::test::TempDir, yuzu::test::process_random_salt

#include <cstdint>
#include <string>
#include <string_view>

#if defined(_WIN32)
#include "execution_artifacts_scratch_identity.hpp" // detail::current_process_token_owner_buf (test reuse)
#include "local_dispatcher.hpp"

#include <yuzu/agent/confined_fs.hpp> // WinHandle
#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

// AFTER windows.h: <winioctl.h> depends on the base Windows types and does
// not include them itself (test_confined_fs_win.cpp's identical ordering
// note) -- REQUIRED for FSCTL_SET_REPARSE_POINT.
#include <winioctl.h>
#include <aclapi.h> // SetNamedSecurityInfoW
#include <sddl.h>   // ConvertStringSidToSidW

#include <win_profiles.hpp> // yuzu::win::PrivilegeScope (SeRestorePrivilege, planted-owner case)

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iomanip>
#include <optional>
#include <sstream>
#include <system_error>
#include <unordered_map>
#include <vector>

// sweep_stale_scratch_dirs() is declared in execution_artifacts_scratch_sweep.hpp
// but DEFINED only in execution_artifacts_scratch_sweep_win.cpp, which
// meson.build compiles exclusively into the execution_artifacts shared_library
// target -- agent_test_exe never links that target (it only loads the built
// .dylib/.dll at runtime by path, via link_depends for build ordering, the
// same pattern test_execution_artifacts_local_dispatcher.cpp relies on). A
// plain call to sweep_stale_scratch_dirs from this TU would therefore leave
// the symbol unresolved at link time. TU-include the .cpp directly instead --
// the same pattern test_execution_artifacts_win_internals.cpp (#4392) already
// uses for execution_artifacts_win.cpp. Unlike that file, nothing here is a
// YUZU_PLUGIN_EXPORT/extern "C" plugin-ABI entry point, so no exclusion-guard
// macro is needed: this TU's own copy of sweep_stale_scratch_dirs coexists
// safely with the separately-loaded real plugin DLL other test cases in this
// binary use, since they are different process modules.
#include "../../agents/plugins/execution_artifacts/src/execution_artifacts_scratch_sweep_win.cpp"
#endif

using namespace yuzu::execution_artifacts;

// ── Portable cases (every OS) ─────────────────────────────────────────────

TEST_CASE("is_scratch_dir_name: accepts the exact prefix + 32 hex (either case), rejects "
          "everything else",
          "[execution_artifacts][scratch_sweep]") {
    CHECK(is_scratch_dir_name("execution_artifacts-0123456789abcdef0123456789abcdef"));
    CHECK(is_scratch_dir_name("execution_artifacts-0123456789ABCDEF0123456789ABCDEF"));
    CHECK(is_scratch_dir_name("execution_artifacts-0123456789AbCdEf0123456789aBcDeF"));

    // 31 hex digits.
    CHECK_FALSE(is_scratch_dir_name("execution_artifacts-0123456789abcdef0123456789abcde"));
    // 33 hex digits.
    CHECK_FALSE(is_scratch_dir_name("execution_artifacts-0123456789abcdef0123456789abcdef0"));
    // non-hex character ('g').
    CHECK_FALSE(is_scratch_dir_name("execution_artifacts-0123456789abcdefg123456789abcdef"));
    // a different prefix entirely.
    CHECK_FALSE(is_scratch_dir_name("other_prefix-0123456789abcdef0123456789abcdef"));
    // case-altered prefix.
    CHECK_FALSE(is_scratch_dir_name("Execution_Artifacts-0123456789abcdef0123456789abcdef"));
    // empty name.
    CHECK_FALSE(is_scratch_dir_name(""));
    // trailing separator.
    CHECK_FALSE(is_scratch_dir_name("execution_artifacts-0123456789abcdef0123456789abcdef/"));
}

TEST_CASE("is_stale: exact-equality age is fresh, one second past is stale, a negative "
          "(future-dated) age is fresh",
          "[execution_artifacts][scratch_sweep]") {
    constexpr std::int64_t kMtime = 1'700'000'000;
    CHECK_FALSE(is_stale(kMtime, kMtime + kScratchDirStaleAfterSecs, kScratchDirStaleAfterSecs));
    CHECK(is_stale(kMtime, kMtime + kScratchDirStaleAfterSecs + 1, kScratchDirStaleAfterSecs));
    // now < mtime -- a future-dated mtime (clock skew).
    CHECK_FALSE(is_stale(kMtime, kMtime - 10, kScratchDirStaleAfterSecs));
}

TEST_CASE("reject_candidate_handle: a reparse attribute or a volume-serial mismatch rejects; a "
          "clean same-volume handle is accepted",
          "[execution_artifacts][scratch_sweep]") {
    constexpr std::uint32_t kDirAttr = 0x00000010; // FILE_ATTRIBUTE_DIRECTORY
    constexpr std::uint32_t kSerial = 0xABCD1234;
    CHECK_FALSE(reject_candidate_handle(kDirAttr, kSerial, kSerial));
    CHECK(reject_candidate_handle(kDirAttr | kFileAttributeReparsePoint, kSerial, kSerial));
    CHECK(reject_candidate_handle(kDirAttr, kSerial + 1, kSerial));
}

TEST_CASE("sweep_start_index: empty -> 0, otherwise pass_counter wraps over the entry count",
          "[execution_artifacts][scratch_sweep]") {
    CHECK(sweep_start_index(0, 0) == 0);
    CHECK(sweep_start_index(7, 0) == 0);
    CHECK(sweep_start_index(0, 3) == 0);
    CHECK(sweep_start_index(2, 3) == 2);
    CHECK(sweep_start_index(3, 3) == 0);
    CHECK(sweep_start_index(8, 3) == 2);
}

TEST_CASE("ClockStepGuard (#4503): steady progression never skips; forward step, backward-then-"
          "restore skip; quarantine expires; boundary is strictly greater",
          "[execution_artifacts][scratch_sweep]") {
    using yuzu::shared::ClockSample;
    using yuzu::shared::ClockStepGuard;
    using yuzu::shared::observe_and_should_skip;
    using yuzu::shared::stepped_forward;
    constexpr std::int64_t kTol = kScratchSweepClockStepToleranceSecs;
    constexpr std::int64_t kQuar = kScratchDirStaleAfterSecs;

    SECTION("steady-only progression never skips") {
        ClockStepGuard g{ClockSample{1000, 10}, ClockStepGuard{}.quarantine_until_steady_s};
        for (std::int64_t i = 1; i <= 20; ++i)
            CHECK_FALSE(observe_and_should_skip(g, {1000 + i * 30, 10 + i * 30}, kTol, kQuar));
    }
    SECTION("forward step skips") {
        ClockStepGuard g{ClockSample{0, 0}, ClockStepGuard{}.quarantine_until_steady_s};
        CHECK(observe_and_should_skip(g, {3700, 1}, kTol, kQuar));
    }
    SECTION("backward step then restoration skips at the restoration, not before") {
        ClockStepGuard g{ClockSample{0, 0}, ClockStepGuard{}.quarantine_until_steady_s};
        CHECK_FALSE(observe_and_should_skip(g, {-3590, 10}, kTol, kQuar));
        CHECK(observe_and_should_skip(g, {20, 20}, kTol, kQuar));
    }
    SECTION("quarantine expires after quarantine_s of steady time with no further step") {
        ClockStepGuard g{ClockSample{0, 0}, ClockStepGuard{}.quarantine_until_steady_s};
        CHECK(observe_and_should_skip(g, {3700, 1}, kTol, kQuar));
        CHECK(observe_and_should_skip(g, {3700 + kQuar - 1, 1 + kQuar - 1}, kTol, kQuar));
        CHECK_FALSE(observe_and_should_skip(g, {3700 + kQuar, 1 + kQuar}, kTol, kQuar));
    }
    SECTION("stepped_forward: exactly the tolerance is no step, one more is") {
        CHECK_FALSE(stepped_forward({0, 0}, {kTol, 0}, kTol));
        CHECK(stepped_forward({0, 0}, {kTol + 1, 0}, kTol));
    }
}

#if defined(_WIN32)

namespace {

namespace fs = std::filesystem;

// ── Fixture helpers ────────────────────────────────────────────────────────

// Raw WriteFile rather than std::ofstream/<fstream> -- test_confined_fs_win.cpp's
// precedent (libc++'s <fstream> branches on _WIN32 internally and expects real
// Windows CRT entry points a syntax-check-only shim cannot supply).
void write_file(const fs::path& path, std::string_view content) {
    const HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                  FILE_ATTRIBUTE_NORMAL, nullptr);
    REQUIRE(h != INVALID_HANDLE_VALUE);
    yuzu::agent::confined_fs::WinHandle owned(h);
    DWORD written = 0;
    REQUIRE(WriteFile(owned.get(), content.data(), static_cast<DWORD>(content.size()), &written,
                       nullptr));
}

// Builds a junction (NTFS mount point) at `link` pointing at `target`, without
// administrator privilege -- copied from test_confined_fs_win.cpp:62-106.
bool create_junction(const fs::path& link, const fs::path& target) {
    if (!CreateDirectoryW(link.c_str(), nullptr))
        return false;

    const HANDLE raw =
        CreateFileW(link.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (raw == INVALID_HANDLE_VALUE)
        return false;
    yuzu::agent::confined_fs::WinHandle handle(raw);

    const std::wstring substitute = L"\\??\\" + fs::absolute(target).wstring();
    const std::wstring print_name = fs::absolute(target).wstring();

    const std::size_t sub_bytes = (substitute.size() + 1) * sizeof(wchar_t);
    const std::size_t print_bytes = (print_name.size() + 1) * sizeof(wchar_t);
    constexpr std::size_t kFixedHeaderSize = 8; // ReparseTag(4) + ReparseDataLength(2) + Reserved(2)
    constexpr std::size_t kMountFieldsSize = 8; // 4 USHORTs: sub/print offset+length

    std::vector<std::byte> buf(kFixedHeaderSize + kMountFieldsSize + sub_bytes + print_bytes);
    const auto put16 = [&](std::size_t off, std::uint16_t v) {
        std::memcpy(buf.data() + off, &v, sizeof(v));
    };
    const auto put32 = [&](std::size_t off, std::uint32_t v) {
        std::memcpy(buf.data() + off, &v, sizeof(v));
    };

    put32(0, IO_REPARSE_TAG_MOUNT_POINT);
    put16(4, static_cast<std::uint16_t>(kMountFieldsSize + sub_bytes + print_bytes));
    put16(6, 0); // Reserved
    put16(8, 0); // SubstituteNameOffset
    put16(10, static_cast<std::uint16_t>(sub_bytes - sizeof(wchar_t)));
    put16(12, static_cast<std::uint16_t>(sub_bytes)); // PrintNameOffset
    put16(14, static_cast<std::uint16_t>(print_bytes - sizeof(wchar_t)));
    std::memcpy(buf.data() + kFixedHeaderSize + kMountFieldsSize, substitute.c_str(), sub_bytes);
    std::memcpy(buf.data() + kFixedHeaderSize + kMountFieldsSize + sub_bytes, print_name.c_str(),
                print_bytes);

    DWORD bytes_returned = 0;
    return DeviceIoControl(handle.get(), FSCTL_SET_REPARSE_POINT, buf.data(),
                            static_cast<DWORD>(buf.size()), nullptr, 0, &bytes_returned,
                            nullptr) != 0;
}

// RemoveDirectory on a reparse-point directory removes the reparse point
// itself, never the target.
struct JunctionCleanup {
    fs::path path;
    ~JunctionCleanup() { RemoveDirectoryW(path.c_str()); }
};

FILETIME unix_seconds_to_filetime(std::int64_t unix_s) {
    constexpr std::int64_t kEpochDeltaSeconds = 11'644'473'600; // 1601 -> 1970
    constexpr std::int64_t kTicksPerSecond = 10'000'000;        // 100ns units
    const auto ticks =
        static_cast<std::uint64_t>((unix_s + kEpochDeltaSeconds) * kTicksPerSecond);
    FILETIME ft{};
    ft.dwLowDateTime = static_cast<DWORD>(ticks & 0xFFFFFFFFull);
    ft.dwHighDateTime = static_cast<DWORD>(ticks >> 32);
    return ft;
}

// Sets `path`'s last-write time explicitly -- never a sleep-then-touch idiom
// (this package's spec). FILE_FLAG_BACKUP_SEMANTICS so this also works on a
// directory.
void set_mtime(const fs::path& path, std::int64_t unix_s) {
    const HANDLE h =
        CreateFileW(path.c_str(), FILE_WRITE_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    REQUIRE(h != INVALID_HANDLE_VALUE);
    yuzu::agent::confined_fs::WinHandle owned(h);
    FILETIME ft = unix_seconds_to_filetime(unix_s);
    REQUIRE(SetFileTime(owned.get(), nullptr, nullptr, &ft));
}

// A name matching is_scratch_dir_name exactly: the real prefix plus 32 hex
// digits, unique per call (process salt + a monotonic counter, never a
// clock -- test_helpers.hpp's flake #473 rationale).
std::string unique_scratch_name() {
    static std::atomic<std::uint64_t> counter{0};
    const std::uint64_t a = yuzu::test::process_random_salt();
    const std::uint64_t b = counter.fetch_add(1, std::memory_order_relaxed);
    std::ostringstream oss;
    oss << kScratchDirPrefix << std::hex << std::setfill('0') << std::setw(16) << a
        << std::setw(16) << b;
    return oss.str();
}

// A scratch-shaped directory containing one small file (the amcache.hve
// stand-in), with its OWN mtime set explicitly last -- creating the inner
// file updates the parent directory's own last-write time on NTFS, so the
// mtime write must come after it.
void create_scratch_dir_with_file(const fs::path& dir, std::int64_t mtime_unix_s) {
    std::error_code ec;
    fs::create_directories(dir, ec);
    REQUIRE_FALSE(ec);
    write_file(dir / "amcache.hve", "0123456789abcdef");
    set_mtime(dir, mtime_unix_s);
}

// Whether THIS test process's token is elevated -- copied from
// test_execution_artifacts_win_local.cpp:129 (plugin_capture.cpp:157's
// precedent).
bool current_process_is_elevated() {
    struct TokenHandle {
        HANDLE h{nullptr};
        ~TokenHandle() {
            if (h)
                CloseHandle(h);
        }
    } token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.h))
        return false;
    TOKEN_ELEVATION te{};
    DWORD got = 0;
    if (!GetTokenInformation(token.h, TokenElevation, &te, sizeof te, &got))
        return false;
    return te.TokenIsElevated != 0;
}

// True iff `sid` equals this process token's own owner SID -- reuses the
// hoisted identity helper rather than re-deriving the owner a second way.
bool sid_is_current_token_owner(PSID sid) {
    const auto owner_buf = yuzu::execution_artifacts::detail::current_process_token_owner_buf();
    if (owner_buf.empty())
        return false;
    const PSID token_owner = reinterpret_cast<const TOKEN_OWNER*>(owner_buf.data())->Owner;
    return EqualSid(sid, token_owner) != 0;
}

// ── Plugin-loading helpers (copied from
//    test_execution_artifacts_win_local.cpp:62-122, used by the g/j e2e
//    cases below) ───────────────────────────────────────────────────────────

void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr) {
        FAIL("execution_artifacts plugin library not found under meson test — the plugin did "
             "not build, or link_depends is not forcing it to build before this test runs");
    }
    WARN("execution_artifacts plugin library not found -- skipping the scratch-sweep e2e checks "
         "(run from the build root, or via `meson test`, to exercise it)");
}

constexpr const char* kPluginExt = ".dll";

fs::path find_execution_artifacts_plugin() {
    const std::string lib_name = std::string{"execution_artifacts"} + kPluginExt;

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" /
                                "execution_artifacts" / lib_name);
    }
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "execution_artifacts" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "execution_artifacts" /
                            lib_name);
    candidates.emplace_back(fs::path{"build-windows"} / "agents" / "plugins" /
                            "execution_artifacts" / lib_name);

    for (const auto& p : candidates) {
        std::error_code ec;
        if (fs::exists(p, ec) && !ec)
            return fs::absolute(p, ec);
    }
    return {};
}

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor;
};

std::optional<LoadedPlugin> load_execution_artifacts_plugin() {
    auto plugin_path = find_execution_artifacts_plugin();
    if (plugin_path.empty())
        return std::nullopt;
    auto handle = yuzu::agent::PluginHandle::load(plugin_path);
    if (!handle.has_value())
        return std::nullopt;
    const auto* descriptor = handle->descriptor();
    if (!descriptor)
        return std::nullopt;
    return LoadedPlugin{std::move(*handle), descriptor};
}

} // namespace

// ── Windows shell: selection + confinement behaviour ────────────────────────

TEST_CASE("sweep_stale_scratch_dirs: removes only the stale scratch dir; fresh, a decoy dir, a "
          "plain file, a junction (and its target), and a dir-with-subdirectory all survive",
          "[execution_artifacts][scratch_sweep]") {
    yuzu::test::TempDir root{"yuzu_test_execart_sweep_"};
    std::error_code ec;
    fs::create_directories(root.path, ec);
    REQUIRE_FALSE(ec);

    constexpr std::int64_t kNow = 2'000'000'000;
    constexpr std::int64_t kStaleMtime = kNow - kScratchDirStaleAfterSecs - 30;
    constexpr std::int64_t kFreshMtime = kNow - 30;

    const std::string stale_name = unique_scratch_name();
    const std::string fresh_name = unique_scratch_name();
    const std::string decoy_name = std::string{kScratchDirPrefix} + "notahexname";
    const std::string plain_file_name = unique_scratch_name();
    const std::string junction_name = unique_scratch_name();
    const std::string subdir_name = unique_scratch_name();

    create_scratch_dir_with_file(root.path / stale_name, kStaleMtime);
    create_scratch_dir_with_file(root.path / fresh_name, kFreshMtime);

    fs::create_directories(root.path / decoy_name, ec);
    REQUIRE_FALSE(ec);
    set_mtime(root.path / decoy_name, kStaleMtime);

    write_file(root.path / plain_file_name, "not-a-directory");
    set_mtime(root.path / plain_file_name, kStaleMtime);

    yuzu::test::TempDir junction_target{"yuzu_test_execart_sweep_target_"};
    fs::create_directories(junction_target.path, ec);
    REQUIRE_FALSE(ec);
    write_file(junction_target.path / "victim.txt", "keep-me");
    const fs::path junction_path = root.path / junction_name;
    REQUIRE(create_junction(junction_path, junction_target.path));
    JunctionCleanup junction_cleanup{junction_path};

    fs::create_directories(root.path / subdir_name, ec);
    REQUIRE_FALSE(ec);
    fs::create_directories(root.path / subdir_name / "nested", ec);
    REQUIRE_FALSE(ec);
    set_mtime(root.path / subdir_name, kStaleMtime);

    const ScratchSweepResult result =
        sweep_stale_scratch_dirs(root.path.wstring(), kNow, kScratchDirStaleAfterSecs);

    CAPTURE(result.removed, result.failed, result.skipped_fresh, result.skipped_not_ours,
            result.deferred);
    CHECK(result.removed == 1);
    CHECK(result.skipped_fresh == 1);
    CHECK(result.failed == 1); // the dir-with-subdirectory candidate
    CHECK(result.skipped_not_ours == 0);

    CHECK_FALSE(fs::exists(root.path / stale_name));
    CHECK(fs::exists(root.path / fresh_name));
    CHECK(fs::exists(root.path / decoy_name));
    CHECK(fs::exists(root.path / plain_file_name));
    CHECK(fs::exists(junction_path));
    CHECK(fs::exists(junction_target.path / "victim.txt"));
    CHECK(fs::exists(root.path / subdir_name));
    CHECK(fs::exists(root.path / subdir_name / "nested"));

    // Idempotence: a second pass over the same tree removes nothing further.
    const ScratchSweepResult second =
        sweep_stale_scratch_dirs(root.path.wstring(), kNow, kScratchDirStaleAfterSecs);
    CHECK(second.removed == 0);
}

TEST_CASE("sweep_stale_scratch_dirs: repeated create+sweep cycles never leave a stale scratch "
          "dir behind (#4390 regression)",
          "[execution_artifacts][scratch_sweep]") {
    yuzu::test::TempDir root{"yuzu_test_execart_sweep_regress_"};
    std::error_code ec;
    fs::create_directories(root.path, ec);
    REQUIRE_FALSE(ec);

    constexpr std::int64_t kNow = 2'000'000'000;
    constexpr std::int64_t kStaleMtime = kNow - kScratchDirStaleAfterSecs - 30;

    for (int i = 0; i < 5; ++i) {
        INFO("iteration " << i);
        const std::string name = unique_scratch_name();
        create_scratch_dir_with_file(root.path / name, kStaleMtime);

        const ScratchSweepResult result =
            sweep_stale_scratch_dirs(root.path.wstring(), kNow, kScratchDirStaleAfterSecs);
        CHECK(result.removed >= 1);

        bool any_scratch_dir_left = false;
        for (const auto& entry : fs::directory_iterator(root.path, ec)) {
            if (is_scratch_dir_name(entry.path().filename().string()))
                any_scratch_dir_left = true;
        }
        CHECK_FALSE(ec);
        CHECK_FALSE(any_scratch_dir_left);
    }
}

TEST_CASE("sweep_stale_scratch_dirs: a non-existent data_dir sets enumerate_error with every "
          "count at zero, and never throws",
          "[execution_artifacts][scratch_sweep]") {
    yuzu::test::TempDir parent{"yuzu_test_execart_sweep_missing_"};
    const fs::path missing = parent.path / "does-not-exist";

    ScratchSweepResult result{};
    REQUIRE_NOTHROW(
        result = sweep_stale_scratch_dirs(missing.wstring(), 2'000'000'000, kScratchDirStaleAfterSecs));

    CHECK(result.enumerate_error);
    CHECK(result.removed == 0);
    CHECK(result.failed == 0);
    CHECK(result.skipped_fresh == 0);
    CHECK(result.skipped_not_ours == 0);
    CHECK(result.deferred == 0);
}

TEST_CASE("sweep_stale_scratch_dirs: a scratch dir held open without FILE_SHARE_DELETE (an "
          "in-flight dispatch's own handle) is never removed; a later sweep removes it once "
          "closed",
          "[execution_artifacts][scratch_sweep]") {
    yuzu::test::TempDir root{"yuzu_test_execart_sweep_inflight_"};
    std::error_code ec;
    fs::create_directories(root.path, ec);
    REQUIRE_FALSE(ec);

    constexpr std::int64_t kNow = 2'000'000'000;
    constexpr std::int64_t kStaleMtime = kNow - kScratchDirStaleAfterSecs - 30;
    const std::string name = unique_scratch_name();
    const fs::path dir = root.path / name;
    create_scratch_dir_with_file(dir, kStaleMtime);

    // Held open WITHOUT FILE_SHARE_DELETE, sharing for read only --
    // execution_artifacts_win.cpp's own open_scratch_dir_handle share mode,
    // the exact protection a live dispatch relies on. DELETE is REQUESTED
    // (never exercised) to match that function's real DesiredAccess: real
    // Windows only counts a handle as a "Deleter" in its per-object
    // share-access bookkeeping when the handle's OWN DesiredAccess claims
    // DELETE -- a FILE_READ_ATTRIBUTES-only handle's lack of
    // FILE_SHARE_DELETE is never enforced against a later opener, however
    // that later opener's own access mask reads. Confirmed empirically on
    // real Windows/MSVC: this test failed before open_scratch_dir_handle
    // was corrected to also request DELETE.
    const HANDLE raw =
        CreateFileW(dir.c_str(), FILE_READ_ATTRIBUTES | DELETE, FILE_SHARE_READ, nullptr,
                    OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    REQUIRE(raw != INVALID_HANDLE_VALUE);
    {
        yuzu::agent::confined_fs::WinHandle held(raw);

        const ScratchSweepResult result =
            sweep_stale_scratch_dirs(root.path.wstring(), kNow, kScratchDirStaleAfterSecs);
        // Windows share-mode checks are per-object: the held handle blocks
        // even the CANDIDATE open (open_candidate_relative requests DELETE
        // specifically so this conflict is detected here, before any child
        // is touched -- see that function's banner), so the directory
        // survives this pass -- never removed, counted failed, and its
        // child file (the amcache.hve stand-in a real live dispatch is
        // actively reading via RegLoadAppKeyW) is never even considered for
        // deletion, not just "also still there by coincidence".
        CHECK(result.removed == 0);
        CHECK(result.failed == 1);
        CHECK(fs::exists(dir));
        CHECK(fs::exists(dir / "amcache.hve"));
    } // `held` closes here.

    const ScratchSweepResult second =
        sweep_stale_scratch_dirs(root.path.wstring(), kNow, kScratchDirStaleAfterSecs);
    CHECK(second.removed == 1);
    CHECK_FALSE(fs::exists(dir));
}

TEST_CASE("sweep_stale_scratch_dirs: a foreign-owned planted scratch dir is skipped, never "
          "removed (elevation-gated)",
          "[execution_artifacts][scratch_sweep]") {
    if (!current_process_is_elevated())
        SKIP("needs elevation to set a foreign owner");

    // SeRestorePrivilege is needed to set an owner other than one already
    // held by this process's token -- win_profiles.hpp's PrivilegeScope.
    yuzu::win::PrivilegeScope restore_priv(L"SeRestorePrivilege");
    if (!restore_priv.ok())
        SKIP("needs elevation to set a foreign owner");

    yuzu::test::TempDir root{"yuzu_test_execart_sweep_owner_"};
    std::error_code ec;
    fs::create_directories(root.path, ec);
    REQUIRE_FALSE(ec);

    constexpr std::int64_t kNow = 2'000'000'000;
    constexpr std::int64_t kStaleMtime = kNow - kScratchDirStaleAfterSecs - 30;
    const std::string name = unique_scratch_name();
    const fs::path dir = root.path / name;
    create_scratch_dir_with_file(dir, kStaleMtime);

    static const wchar_t* const kCandidateSids[] = {L"S-1-5-19", L"S-1-5-18", L"S-1-5-32-544"};
    PSID foreign_sid = nullptr;
    for (const wchar_t* sid_str : kCandidateSids) {
        PSID candidate = nullptr;
        if (!ConvertStringSidToSidW(sid_str, &candidate))
            continue;
        if (!sid_is_current_token_owner(candidate)) {
            foreign_sid = candidate;
            break;
        }
        LocalFree(candidate);
    }
    if (foreign_sid == nullptr)
        SKIP("no candidate SID differs from the current token owner");

    const DWORD set_rc =
        SetNamedSecurityInfoW(const_cast<LPWSTR>(dir.c_str()), SE_FILE_OBJECT,
                              OWNER_SECURITY_INFORMATION, foreign_sid, nullptr, nullptr, nullptr);
    LocalFree(foreign_sid);
    if (set_rc != ERROR_SUCCESS)
        SKIP("needs elevation to set a foreign owner");

    const ScratchSweepResult result =
        sweep_stale_scratch_dirs(root.path.wstring(), kNow, kScratchDirStaleAfterSecs);
    CHECK(result.skipped_not_ours == 1);
    CHECK(result.removed == 0);
    CHECK(fs::exists(dir));
}

// ── Independent caps, root-cap limit, entry/wall caps, starvation (#4504/#4505) ──

namespace {

// Fixed, sort-ordered scratch names ("execution_artifacts-" + 32 hex): NTFS
// enumerates in name order, so a numeric prefix forces the visit order that
// random unique_scratch_name() cannot. `idx` < 100.
std::string ordered_scratch_name(unsigned idx) {
    std::ostringstream oss;
    oss << kScratchDirPrefix << std::setfill('0') << std::setw(32) << idx;
    return oss.str();
}

// A stale scratch-shaped dir that the sweep counts as `failed` (a subdirectory).
void create_failing_scratch_dir(const fs::path& dir, std::int64_t mtime_unix_s) {
    std::error_code ec;
    fs::create_directories(dir / "nested", ec);
    REQUIRE_FALSE(ec);
    set_mtime(dir, mtime_unix_s);
}

constexpr std::int64_t kSweepNow = 2'000'000'000;
constexpr std::int64_t kSweepStale = kSweepNow - kScratchDirStaleAfterSecs - 30;

} // namespace

TEST_CASE("sweep_stale_scratch_dirs: removal and failure caps are independent (#4505)",
          "[execution_artifacts][scratch_sweep]") {
    yuzu::test::TempDir root{"yuzu_test_execart_sweep_caps_"};
    std::error_code ec;
    fs::create_directories(root.path, ec);
    REQUIRE_FALSE(ec);

    // Order F R F R F R: the pass stops before the 5th entry (removed 2, failed 2),
    // so the third removable is deferred, not reached.
    create_failing_scratch_dir(root.path / ordered_scratch_name(1), kSweepStale);
    create_scratch_dir_with_file(root.path / ordered_scratch_name(2), kSweepStale);
    create_failing_scratch_dir(root.path / ordered_scratch_name(3), kSweepStale);
    create_scratch_dir_with_file(root.path / ordered_scratch_name(4), kSweepStale);
    create_failing_scratch_dir(root.path / ordered_scratch_name(5), kSweepStale);
    create_scratch_dir_with_file(root.path / ordered_scratch_name(6), kSweepStale);

    const ScratchSweepResult r =
        sweep_stale_scratch_dirs(root.path.wstring(), kSweepNow, kScratchDirStaleAfterSecs,
                                 SweepLimits{.max_removals = 2, .max_failures = 2}, 0);
    CAPTURE(r.removed, r.failed, r.deferred);
    CHECK(r.removed == 2);
    CHECK(r.failed == 2);
    CHECK(r.deferred >= 1);
    CHECK(fs::exists(root.path / ordered_scratch_name(6)));
}

TEST_CASE("sweep_stale_scratch_dirs: root entry cap defers visibly; rotation does not reach past "
          "it (documented limitation, #4504)",
          "[execution_artifacts][scratch_sweep]") {
    SECTION("removable entries: the cap defers, later passes make progress") {
        yuzu::test::TempDir root{"yuzu_test_execart_sweep_rootcap_"};
        std::error_code ec;
        fs::create_directories(root.path, ec);
        REQUIRE_FALSE(ec);
        for (unsigned i = 1; i <= 4; ++i)
            create_scratch_dir_with_file(root.path / ordered_scratch_name(i), kSweepStale);

        const SweepLimits lim{.max_root_entries = 2};
        const ScratchSweepResult first = sweep_stale_scratch_dirs(
            root.path.wstring(), kSweepNow, kScratchDirStaleAfterSecs, lim, 0);
        CHECK(first.removed == 2);
        CHECK(first.deferred >= 1); // truncated enumeration is never silent
        const ScratchSweepResult second = sweep_stale_scratch_dirs(
            root.path.wstring(), kSweepNow, kScratchDirStaleAfterSecs, lim, 1);
        CHECK(second.removed == 2);
    }
    SECTION("persistent failures inside the cap hide later entries on every pass") {
        // Rotation only reorders the entries the capped enumeration returned.
        // The two failing dirs sort first and fill the root cap, so the two
        // removable orphans behind them are never reached, on any pass. A future
        // resumable enumeration must change this assertion deliberately.
        yuzu::test::TempDir root{"yuzu_test_execart_sweep_rootcap_lim_"};
        std::error_code ec;
        fs::create_directories(root.path, ec);
        REQUIRE_FALSE(ec);
        create_failing_scratch_dir(root.path / ordered_scratch_name(1), kSweepStale);
        create_failing_scratch_dir(root.path / ordered_scratch_name(2), kSweepStale);
        create_scratch_dir_with_file(root.path / ordered_scratch_name(3), kSweepStale);
        create_scratch_dir_with_file(root.path / ordered_scratch_name(4), kSweepStale);

        std::size_t total_removed = 0;
        for (std::uint64_t pass = 0; pass < 8; ++pass) {
            INFO("pass " << pass);
            const ScratchSweepResult r =
                sweep_stale_scratch_dirs(root.path.wstring(), kSweepNow, kScratchDirStaleAfterSecs,
                                         SweepLimits{.max_root_entries = 2}, pass);
            CHECK(r.deferred >= 1);
            total_removed += r.removed;
        }
        CHECK(total_removed <= 2);
        CHECK(total_removed == 0);
        CHECK(fs::exists(root.path / ordered_scratch_name(3)));
        CHECK(fs::exists(root.path / ordered_scratch_name(4)));
    }
}

TEST_CASE("sweep_stale_scratch_dirs: a candidate with more than max_dir_entries files fails "
          "and nothing inside is deleted",
          "[execution_artifacts][scratch_sweep]") {
    yuzu::test::TempDir root{"yuzu_test_execart_sweep_direntries_"};
    std::error_code ec;
    fs::create_directories(root.path, ec);
    REQUIRE_FALSE(ec);

    const SweepLimits lim{.max_dir_entries = 3};
    const fs::path dir = root.path / unique_scratch_name();
    fs::create_directories(dir, ec);
    REQUIRE_FALSE(ec);
    for (std::size_t i = 0; i < lim.max_dir_entries + 1; ++i)
        write_file(dir / ("f" + std::to_string(i)), "x");
    set_mtime(dir, kSweepStale);

    const ScratchSweepResult r = sweep_stale_scratch_dirs(
        root.path.wstring(), kSweepNow, kScratchDirStaleAfterSecs, lim, 0);
    CHECK(r.removed == 0);
    CHECK(r.failed == 1);
    for (std::size_t i = 0; i < lim.max_dir_entries + 1; ++i)
        CHECK(fs::exists(dir / ("f" + std::to_string(i))));
}

TEST_CASE("sweep_stale_scratch_dirs: an already-expired wall deadline defers and removes nothing",
          "[execution_artifacts][scratch_sweep]") {
    yuzu::test::TempDir root{"yuzu_test_execart_sweep_deadline_"};
    std::error_code ec;
    fs::create_directories(root.path, ec);
    REQUIRE_FALSE(ec);
    const fs::path dir = root.path / unique_scratch_name();
    create_scratch_dir_with_file(dir, kSweepStale);

    // The deadline is computed once per pass; with max_wall_ms = 0 it is past
    // by the first check, whether enumeration or the per-candidate check trips.
    const ScratchSweepResult r =
        sweep_stale_scratch_dirs(root.path.wstring(), kSweepNow, kScratchDirStaleAfterSecs,
                                 SweepLimits{.max_wall_ms = 0}, 0);
    CHECK(r.removed == 0);
    CHECK(r.deferred >= 1);
    CHECK(fs::exists(dir / "amcache.hve"));
}

// Missing-mtime branch (`!entry.meta.mtime` -> failed, never "old"): NTFS always
// reports a last-write time, so a fixture cannot make entry.meta.mtime nullopt
// and the branch is not exercised here. Its contract -- absence is never treated
// as stale -- is the same one is_stale() pins above (a future-dated age is fresh).

TEST_CASE("sweep_stale_scratch_dirs: persistent failures sorting first cannot starve a later "
          "orphan across rotated passes (#4504)",
          "[execution_artifacts][scratch_sweep]") {
    yuzu::test::TempDir root{"yuzu_test_execart_sweep_starve_"};
    std::error_code ec;
    fs::create_directories(root.path, ec);
    REQUIRE_FALSE(ec);
    for (unsigned i = 1; i <= 5; ++i)
        create_failing_scratch_dir(root.path / ordered_scratch_name(i), kSweepStale);
    const fs::path orphan = root.path / ordered_scratch_name(6);
    create_scratch_dir_with_file(orphan, kSweepStale);

    const SweepLimits lim{.max_removals = 1, .max_failures = 2};
    for (std::uint64_t pass = 0; pass < 7; ++pass) {
        INFO("pass " << pass);
        const ScratchSweepResult r = sweep_stale_scratch_dirs(
            root.path.wstring(), kSweepNow, kScratchDirStaleAfterSecs, lim, pass);
        CHECK(r.removed <= lim.max_removals);
    }
    CHECK_FALSE(fs::exists(orphan));
}

// ── Real plugin end-to-end (init() / pre-dispatch) ──────────────────────────

TEST_CASE("execution_artifacts init(): a stale planted scratch dir is swept away at startup; a "
          "fresh one survives",
          "[execution_artifacts][scratch_sweep]") {
    auto plugin = load_execution_artifacts_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::test::TempDir data_dir("yuzu_test_execart_sweep_init_");
    std::error_code ec;
    fs::create_directories(data_dir.path, ec);
    REQUIRE_FALSE(ec);

    // init()'s sweep uses the REAL wall clock, so "stale" here is relative
    // to now, not to a fixture-chosen `now`.
    const auto real_now_s = std::chrono::duration_cast<std::chrono::seconds>(
                                std::chrono::system_clock::now().time_since_epoch())
                                .count();
    const std::string stale_name = unique_scratch_name();
    const std::string fresh_name = unique_scratch_name();
    create_scratch_dir_with_file(data_dir.path / stale_name,
                                 real_now_s - kScratchDirStaleAfterSecs - 30);
    create_scratch_dir_with_file(data_dir.path / fresh_name, real_now_s - 5);

    yuzu::agent::StandalonePluginContext ctx(
        "execution_artifacts",
        std::unordered_map<std::string, std::string>{{"agent.data_dir", data_dir.path.string()}});
    REQUIRE(plugin->descriptor->init(ctx.get()) == 0);

    CHECK_FALSE(fs::exists(data_dir.path / stale_name));
    CHECK(fs::exists(data_dir.path / fresh_name));

    if (plugin->descriptor->shutdown)
        plugin->descriptor->shutdown(ctx.get());
}

TEST_CASE("execution_artifacts amcache dispatch: a newly planted stale scratch dir is swept "
          "before the leg runs",
          "[execution_artifacts][scratch_sweep]") {
    auto plugin = load_execution_artifacts_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::test::TempDir data_dir("yuzu_test_execart_sweep_predispatch_");
    std::error_code ec;
    fs::create_directories(data_dir.path, ec);
    REQUIRE_FALSE(ec);

    yuzu::agent::StandalonePluginContext ctx(
        "execution_artifacts",
        std::unordered_map<std::string, std::string>{{"agent.data_dir", data_dir.path.string()}});
    REQUIRE(plugin->descriptor->init(ctx.get()) == 0);

    const auto real_now_s = std::chrono::duration_cast<std::chrono::seconds>(
                                std::chrono::system_clock::now().time_since_epoch())
                                .count();
    const std::string stale_name = unique_scratch_name();
    create_scratch_dir_with_file(data_dir.path / stale_name,
                                 real_now_s - kScratchDirStaleAfterSecs - 30);

    yuzu::agent::LocalDispatcher dispatcher;
    (void)dispatcher.run(plugin->descriptor, "amcache"); // rc ignored -- may be constrained unelevated

    CHECK_FALSE(fs::exists(data_dir.path / stale_name));

    if (plugin->descriptor->shutdown)
        plugin->descriptor->shutdown(ctx.get());
}

TEST_CASE("execution_artifacts amcache dispatch: a fresh planted scratch dir is never swept "
          "(#4503)",
          "[execution_artifacts][scratch_sweep]") {
    // The in-process clock-step skip cannot be forced from a test (the plugin has
    // no clock seam); the pure ClockStepGuard cases above pin that decision.
    // This pins the observable invariant either way: a fresh dir survives.
    auto plugin = load_execution_artifacts_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::test::TempDir data_dir("yuzu_test_execart_sweep_fresh_");
    std::error_code ec;
    fs::create_directories(data_dir.path, ec);
    REQUIRE_FALSE(ec);

    yuzu::agent::StandalonePluginContext ctx(
        "execution_artifacts",
        std::unordered_map<std::string, std::string>{{"agent.data_dir", data_dir.path.string()}});
    REQUIRE(plugin->descriptor->init(ctx.get()) == 0);

    const auto real_now_s = std::chrono::duration_cast<std::chrono::seconds>(
                                std::chrono::system_clock::now().time_since_epoch())
                                .count();
    const std::string fresh_name = unique_scratch_name();
    create_scratch_dir_with_file(data_dir.path / fresh_name, real_now_s);

    yuzu::agent::LocalDispatcher dispatcher;
    (void)dispatcher.run(plugin->descriptor, "amcache");

    CHECK(fs::exists(data_dir.path / fresh_name));

    if (plugin->descriptor->shutdown)
        plugin->descriptor->shutdown(ctx.get());
}

#endif // defined(_WIN32)
