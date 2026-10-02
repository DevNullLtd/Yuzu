/**
 * test_privacy_permissions_win_internals.cpp -- TU-inclusion seam over
 * privacy_permissions_win.cpp's internal-linkage StabilityWatch, walk_consent_store and
 * HiveFileGuard. The pure classifiers (classify_stability, classify_hive_file, ...) are covered
 * in test_privacy_permissions_parsers.cpp; these cases prove the production WIRING around them:
 * that the watch is armed and polled, that the walk decodes a ConsentStore subtree and honours the
 * deadline, and that the guard checks the deadline first and verifies the file identity. No fake
 * registry interface: a per-process-salted volatile HKCU key and a TempDir file.
 *
 * `#if defined(_WIN32)` guards the WHOLE body -- empty TU elsewhere (the same shape as
 * test_execution_artifacts_win_internals.cpp and test_privacy_permissions_macos_internals.cpp).
 */
#if !defined(_WIN32)

// Nothing to test off Windows -- see the file banner above.

#else // defined(_WIN32)

#include <catch2/catch_test_macros.hpp>

#include "test_helpers.hpp"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

// The leg's anonymous-namespace helpers have no header seam; the guard macro drops the
// plugin-facing collect_windows_permissions so this TU can include the file. Never defined by the
// real build. Excluding that function leaves helpers with no caller in THIS compilation: MSVC's
// C4505 (unused static function) is silenced narrowly around the include.
#define YUZU_PRIVACY_PERMISSIONS_WIN_UNIT_TEST_INTERNALS_ONLY 1
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4505)
#endif
#include "../../agents/plugins/privacy_permissions/src/privacy_permissions_win.cpp"
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
#undef YUZU_PRIVACY_PERMISSIONS_WIN_UNIT_TEST_INTERNALS_ONLY

using namespace yuzu::privacy_permissions;

namespace {

constexpr wchar_t kStorePath[] =
    L"Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore";

/// A salted volatile key under HKCU, deleted (with its subtree) on scope exit.
struct TestKey {
    std::wstring sub_path;
    HKEY root = nullptr;

    TestKey() {
        static std::atomic<std::uint64_t> counter{0};
        const auto n = counter.fetch_add(1, std::memory_order_relaxed);
        const std::string sub = "Software\\Yuzu\\yuzu_test_privperm_" +
                                std::to_string(::GetCurrentProcessId()) + "_" +
                                std::to_string(yuzu::test::process_random_salt()) + "_" +
                                std::to_string(n);
        sub_path = yuzu::win::to_wide(sub);
        REQUIRE(RegCreateKeyExW(HKEY_CURRENT_USER, sub_path.c_str(), 0, nullptr,
                                REG_OPTION_VOLATILE, KEY_READ | KEY_WRITE, nullptr, &root,
                                nullptr) == ERROR_SUCCESS);
    }
    ~TestKey() {
        if (root) RegCloseKey(root);
        RegDeleteTreeW(HKEY_CURRENT_USER, sub_path.c_str());
    }
    TestKey(const TestKey&) = delete;
    TestKey& operator=(const TestKey&) = delete;

    /// Creates `<root>\<rel>` (every level) and returns it open for writing.
    yuzu::win::RegKey make(const std::wstring& rel) const {
        yuzu::win::RegKey k;
        REQUIRE(RegCreateKeyExW(root, rel.c_str(), 0, nullptr, REG_OPTION_VOLATILE,
                                KEY_READ | KEY_WRITE, nullptr, k.put(), nullptr) == ERROR_SUCCESS);
        return k;
    }
};

void set_sz(HKEY key, const wchar_t* name, const std::wstring& value) {
    REQUIRE(RegSetValueExW(key, name, 0, REG_SZ, reinterpret_cast<const BYTE*>(value.c_str()),
                           static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t))) ==
            ERROR_SUCCESS);
}

void set_qword(HKEY key, const wchar_t* name, std::uint64_t v) {
    REQUIRE(RegSetValueExW(key, name, 0, REG_QWORD, reinterpret_cast<const BYTE*>(&v), sizeof v) ==
            ERROR_SUCCESS);
}

/// The calling process's own user SID as a string (the owner of a file the test creates is this
/// user, or BUILTIN\Administrators when elevated: both are in the allow-set).
std::string own_sid_string() {
    HANDLE token = nullptr;
    REQUIRE(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token));
    DWORD need = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &need);
    std::vector<BYTE> buf(need);
    REQUIRE(GetTokenInformation(token, TokenUser, buf.data(), need, &need));
    CloseHandle(token);
    LPWSTR s = nullptr;
    REQUIRE(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buf.data())->User.Sid, &s));
    std::string out = yuzu::win::from_wide(s);
    LocalFree(s);
    return out;
}

const RawGrant* find(const std::vector<RawGrant>& v, std::string_view app, std::string_view cat) {
    for (const auto& g : v)
        if (g.app_id == app && g.category == cat) return &g;
    return nullptr;
}

} // namespace

TEST_CASE("privacy_permissions win: StabilityWatch reports a change armed beneath the root and "
          "is stable when nothing moved",
          "[privacy_permissions][win_internals]") {
    TestKey key;
    {
        StabilityWatch quiet(key.root);
        CHECK_FALSE(win::classify_stability(quiet.poll()).has_value());
    }
    StabilityWatch watch(key.root);
    const auto child = key.make(L"child");
    set_sz(child.get(), L"Value", L"Deny"); // a change beneath the armed root, before the poll
    const auto token = win::classify_stability(watch.poll());
    REQUIRE(token.has_value());
    CHECK(*token == "changed_during_read");
}

TEST_CASE("privacy_permissions win: walk_consent_store decodes a fixture ConsentStore, reports a "
          "missing store, and stops at an expired deadline",
          "[privacy_permissions][win_internals]") {
    TestKey key;
    const std::wstring store = kStorePath;
    set_sz(key.make(store + L"\\webcam").get(), L"Value", L"Allow");
    set_sz(key.make(store + L"\\webcam\\Pkg.App_1").get(), L"Value", L"Allow");
    key.make(store + L"\\webcam\\NonPackaged"); // the toggle: no Value -> absent
    {
        const auto app = key.make(store + L"\\webcam\\NonPackaged\\C:#app#x.exe");
        set_sz(app.get(), L"Value", L"Deny");
        set_qword(app.get(), L"LastUsedTimeStart", 116444736000000000ULL + 10000ULL); // 1 ms
    }
    set_sz(key.make(store + L"\\microphone").get(), L"Value", L"Prompt"); // unmodelled literal

    SECTION("the fixture is decoded level by level; unmodelled and missing keys stay visible") {
        win::RetentionBudget budget;
        const auto w = walk_consent_store(key.root, budget);
        CHECK(w.root_rc == ERROR_SUCCESS);
        CHECK(w.refused.empty());
        CHECK(w.structural.empty());
        const auto* cam = find(w.grants, "-", "camera");
        REQUIRE(cam);
        CHECK(cam->state == PermissionState::allowed);
        const auto* pkg = find(w.grants, "Pkg.App_1", "camera");
        REQUIRE(pkg);
        CHECK(pkg->state == PermissionState::allowed);
        const auto* toggle = find(w.grants, "NonPackaged", "camera");
        REQUIRE(toggle);
        CHECK(toggle->state == PermissionState::absent);
        const auto* exe = find(w.grants, "C:\\app\\x.exe", "camera");
        REQUIRE(exe);
        CHECK(exe->state == PermissionState::denied);
        CHECK_FALSE(exe->read_denied); // a decoded Deny is not a refused read
        CHECK(exe->last_used_start.value == "1");
        const auto* mic = find(w.grants, "-", "microphone");
        REQUIRE(mic);
        CHECK(mic->state == PermissionState::prompt_undetermined);
        const auto* loc = find(w.grants, "-", "location"); // no key at all: absent, not omitted
        REQUIRE(loc);
        CHECK(loc->state == PermissionState::absent);
    }
    SECTION("a missing ConsentStore reads file-not-found and every category absent") {
        TestKey empty;
        win::RetentionBudget budget;
        const auto w = walk_consent_store(empty.root, budget);
        CHECK(w.root_rc == ERROR_FILE_NOT_FOUND);
        CHECK(w.grants.size() == win::kCapabilities.size());
        for (const auto& g : w.grants) CHECK(g.state == PermissionState::absent);
    }
    SECTION("an already-expired deadline stops the walk before any key is read") {
        win::RetentionBudget budget;
        budget.deadline = std::chrono::steady_clock::now() - std::chrono::seconds{1};
        const auto w = walk_consent_store(key.root, budget);
        CHECK(budget.timed_out);
        CHECK(w.grants.empty());
    }
}

TEST_CASE("privacy_permissions win: HiveFileGuard checks the deadline before any open, accepts a "
          "regular file, refuses a directory or a missing file, and catches a swapped file",
          "[privacy_permissions][win_internals]") {
    yuzu::test::TempDir tmp("yuzu_test_privperm_hive_");
    fs::create_directories(tmp.path);
    const fs::path dir = fs::canonical(tmp.path); // the final path the kernel reports
    const fs::path file = dir / "hive.bin";
    { std::ofstream(file, std::ios::binary) << "regf"; }
    const std::string sid = own_sid_string();

    SECTION("an expired deadline is refused as `timeout` with no file opened") {
        win::RetentionBudget budget;
        budget.deadline = std::chrono::steady_clock::now() - std::chrono::seconds{1};
        HiveFileGuard guard{budget, sid, 0, std::nullopt};
        CHECK(guard.before_load(file.wstring()) == "timeout");
        CHECK(guard.opens == 0);
    }
    SECTION("a regular file owned by the calling user is accepted, and its identity re-verifies") {
        win::RetentionBudget budget;
        HiveFileGuard guard{budget, sid, 0, std::nullopt};
        CHECK(guard.before_load(file.wstring()) == "");
        CHECK(guard.after_load(file.wstring()) == "");
    }
    SECTION("a directory is not a regular file") {
        win::RetentionBudget budget;
        HiveFileGuard guard{budget, sid, 0, std::nullopt};
        CHECK(guard.before_load(dir.wstring()) == "hive_not_regular");
    }
    SECTION("a missing file is a stat failure carrying the Win32 code") {
        win::RetentionBudget budget;
        HiveFileGuard guard{budget, sid, 0, std::nullopt};
        CHECK(guard.before_load((dir / "missing.bin").wstring()) == "hive_stat_failed:win32_2");
    }
    SECTION("a UNC path is refused before any syscall") {
        win::RetentionBudget budget;
        HiveFileGuard guard{budget, sid, 0, std::nullopt};
        CHECK(guard.before_load(L"\\\\server\\share\\NTUSER.DAT") == "hive_path_unc");
        CHECK(guard.opens == 0);
    }
    SECTION("a different file at the same path after the load is hive_identity_changed") {
        win::RetentionBudget budget;
        HiveFileGuard guard{budget, sid, 0, std::nullopt};
        REQUIRE(guard.before_load(file.wstring()) == "");
        const fs::path other = dir / "other.bin";
        { std::ofstream(other, std::ios::binary) << "regf"; }
        fs::rename(file, dir / "moved.bin");
        fs::rename(other, file);
        CHECK(guard.after_load(file.wstring()) == "hive_identity_changed");
    }
    SECTION("after_load with no before_load snapshot refuses") {
        win::RetentionBudget budget;
        HiveFileGuard guard{budget, sid, 0, std::nullopt};
        CHECK(guard.after_load(file.wstring()) == "hive_identity_changed");
    }
}

#endif // defined(_WIN32)
