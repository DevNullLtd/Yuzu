/**
 * test_privacy_permissions_win_internals.cpp -- TU-inclusion seam over
 * privacy_permissions_win.cpp's internal-linkage StabilityWatch, walk_consent_store and
 * HiveFileGuard. The pure classifiers (classify_stability, classify_hive_file, ...) are covered
 * in test_privacy_permissions_parsers.cpp; these cases prove the production WIRING around them:
 * that the watch is armed and polled, that the walk decodes a ConsentStore subtree and honours the
 * deadline, that the guard checks the deadline first and verifies the file identity, that
 * with_user_hive reads a loaded hive before ever entering the offline arm, and that the final-path
 * comparison is Windows' own ordinal one. No fake registry interface: a per-process-salted volatile
 * HKCU key and a TempDir file.
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
#include <stdexcept>
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

#include <winioctl.h> // FSCTL_SET_SPARSE (the sparse-file oversize fixture)

using namespace yuzu::privacy_permissions;

namespace {

constexpr wchar_t kStorePath[] =
    L"Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore";

/// A salted volatile key under HKCU, deleted (with its subtree) on scope exit.
struct TestKey {
    std::wstring sub_path;
    HKEY root = nullptr;

    /// `volatile_key = false` makes the key savable with RegSaveKeyExW (it saves only
    /// non-volatile keys); the destructor deletes it either way.
    explicit TestKey(bool volatile_key = true) {
        static std::atomic<std::uint64_t> counter{0};
        const auto n = counter.fetch_add(1, std::memory_order_relaxed);
        const std::string sub = "Software\\Yuzu\\yuzu_test_privperm_" +
                                std::to_string(::GetCurrentProcessId()) + "_" +
                                std::to_string(yuzu::test::process_random_salt()) + "_" +
                                std::to_string(n);
        sub_path = yuzu::win::to_wide(sub);
        REQUIRE(RegCreateKeyExW(HKEY_CURRENT_USER, sub_path.c_str(), 0, nullptr,
                                volatile_key ? REG_OPTION_VOLATILE : REG_OPTION_NON_VOLATILE,
                                KEY_READ | KEY_WRITE, nullptr, &root, nullptr) == ERROR_SUCCESS);
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

/// The calling process's own TOKEN_USER (the SID pointer points into the returned buffer).
std::vector<BYTE> own_token_user() {
    HANDLE raw = nullptr;
    REQUIRE(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw));
    const UniqueHandle token{raw};
    DWORD need = 0;
    GetTokenInformation(token.h, TokenUser, nullptr, 0, &need);
    std::vector<BYTE> buf(need);
    REQUIRE(GetTokenInformation(token.h, TokenUser, buf.data(), need, &need));
    return buf;
}

PSID sid_of(std::vector<BYTE>& token_user) {
    return reinterpret_cast<TOKEN_USER*>(token_user.data())->User.Sid;
}

/// The calling process's own user SID as a string (the owner of a file the test creates is this
/// user, or BUILTIN\Administrators when elevated: both are in the allow-set).
std::string own_sid_string() {
    auto user = own_token_user();
    LPWSTR s = nullptr;
    REQUIRE(ConvertSidToStringSidW(sid_of(user), &s));
    const LocalFreeGuard guard{s};
    return yuzu::win::from_wide(s);
}

/// A SID no real profile carries: the offline arm is the only way to reach its "profile". The
/// last sub-authority is salted per process (a fixed width, so no SID is a prefix of another):
/// two concurrent test jobs on a shared runner never see each other's mounts (CLAUDE.md #1871).
const std::string& synthetic_sid() {
    static const std::string sid = [] {
        const auto salted = 1'000'000'000u + yuzu::test::process_random_salt() % 3'000'000'000u;
        return "S-1-5-21-1-2-3-" + std::to_string(salted); // always 10 digits
    }();
    return sid;
}

/// Whether any HKEY_USERS subkey is an offline mount this process made for the synthetic SID.
bool synthetic_mount_present() {
    for (const auto& n : yuzu::win::enumerate_hku_subkeys())
        if (n.find(synthetic_sid()) != std::string::npos) return true;
    return false;
}

/// Mandatory cleanup on every path: the shared box must never keep a YUZU_HIVE_* mount. `held` is
/// released first (a handle held on the mount's root keeps it from unloading).
struct HiveCleanup {
    yuzu::win::RegKey& held;
    const yuzu::win::HiveAccessReport& report;
    void run() const {
        held.reset();
        if (!report.mounted_offline) return;
        // with_user_hive's privilege scopes have already reverted: unloading needs both again.
        const yuzu::win::PrivilegeScope restore(L"SeRestorePrivilege");
        const yuzu::win::PrivilegeScope backup(L"SeBackupPrivilege");
        RegUnLoadKeyW(HKEY_USERS, yuzu::win::to_wide(report.mount_name).c_str());
    }
    ~HiveCleanup() { run(); }
};

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
    // Created BEFORE arming: production watches Value writes at depth >= 2 (a capability's app
    // key), so only a LAST_SET change beneath a subtree watch trips this, not a name change.
    const auto grandchild = key.make(L"child\\grandchild");
    {
        StabilityWatch quiet(key.root);
        CHECK_FALSE(win::classify_stability(quiet.poll()).has_value());
    }
    StabilityWatch watch(key.root);
    set_sz(grandchild.get(), L"Value", L"Deny"); // a depth-2 Value write after arming
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
    // Hostile Value shapes under the owning user's write access: each is reported, never decoded.
    set_sz(key.make(store + L"\\webcam\\Pkg.Big").get(), L"Value",
           std::wstring(win::kMaxConsentValueBytes, L'x')); // > kMaxConsentValueBytes bytes
    REQUIRE(RegSetValueExW(key.make(store + L"\\webcam\\Pkg.Empty").get(), L"Value", 0, REG_SZ,
                           nullptr, 0) == ERROR_SUCCESS); // present, zero bytes
    {
        const DWORD one = 1;
        REQUIRE(RegSetValueExW(key.make(store + L"\\webcam\\Pkg.Dword").get(), L"Value", 0,
                               REG_DWORD, reinterpret_cast<const BYTE*>(&one),
                               sizeof one) == ERROR_SUCCESS);
    }

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
    SECTION("hostile Value shapes are unreadable with a named cause, never decoded or allocated") {
        win::RetentionBudget budget;
        const auto w = walk_consent_store(key.root, budget);
        const auto* big = find(w.grants, "Pkg.Big", "camera");
        REQUIRE(big);
        CHECK(big->state == PermissionState::unreadable);
        CHECK(big->cause == "value_oversized");
        CHECK(big->raw_value == "-"); // the oversized value is never read
        const auto* empty = find(w.grants, "Pkg.Empty", "camera");
        REQUIRE(empty);
        CHECK(empty->state == PermissionState::unreadable);
        CHECK(empty->cause == "value_empty");
        const auto* dword = find(w.grants, "Pkg.Dword", "camera");
        REQUIRE(dword);
        CHECK(dword->state == PermissionState::unreadable);
        CHECK(dword->cause == "value_type_" + std::to_string(REG_DWORD));
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
        CHECK(budget.timed_out); // the side effect assemble_windows_rows relies on to end the run
    }
    SECTION("a regular file owned by the calling user is accepted, and its identity re-verifies") {
        win::RetentionBudget budget;
        HiveFileGuard guard{budget, sid, 0, std::nullopt};
        CHECK(guard.before_load(file.wstring()) == "");
        CHECK(guard.after_load(file.wstring()) == "");
    }
    SECTION("a doubled separator before the file name is still the same path") {
        win::RetentionBudget budget;
        HiveFileGuard guard{budget, sid, 0, std::nullopt};
        const std::wstring doubled = dir.wstring() + L"\\\\hive.bin";
        CHECK(guard.before_load(doubled) == "");
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
    SECTION("a path deeper than kMaxHivePathDepth is refused before any syscall") {
        win::RetentionBudget budget;
        HiveFileGuard guard{budget, sid, 0, std::nullopt};
        std::wstring deep = dir.wstring().substr(0, 3); // the drive root of a fixed disk
        for (std::size_t i = 0; i < win::kMaxHivePathDepth; ++i) deep += L"d\\";
        deep += L"NTUSER.DAT"; // kMaxHivePathDepth directories + the leaf = one over
        CHECK(guard.before_load(deep) == "hive_path_too_deep");
        CHECK(guard.opens == 0);
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

namespace {

/// A TempDir holding one regular `hive.bin`; `dir` is the final path the kernel reports.
struct HiveDir {
    yuzu::test::TempDir tmp{"yuzu_test_privperm_hive_"};
    fs::path dir, file;
    HiveDir() {
        fs::create_directories(tmp.path);
        dir = fs::canonical(tmp.path);
        file = dir / "hive.bin";
        std::ofstream(file, std::ios::binary) << "regf";
    }
};

} // namespace

TEST_CASE("privacy_permissions win: HiveFileGuard refuses a drive that is not a fixed disk with "
          "no file opened",
          "[privacy_permissions][win_internals]") {
    wchar_t letter = 0;
    for (wchar_t c = L'A'; c <= L'Z' && !letter; ++c) {
        const wchar_t root[] = {c, L':', L'\\', L'\0'};
        if (GetDriveTypeW(root) == DRIVE_NO_ROOT_DIR) letter = c;
    }
    if (!letter) SKIP("every drive letter is mapped: no DRIVE_NO_ROOT_DIR root to refuse");
    win::RetentionBudget budget;
    HiveFileGuard guard{budget, synthetic_sid(), 0, std::nullopt};
    CHECK(guard.before_load(std::wstring{letter} + L":\\Users\\x\\NTUSER.DAT") ==
          "hive_path_not_fixed");
    CHECK(guard.opens == 0);
}

TEST_CASE("privacy_permissions win: HiveFileGuard refuses a symlinked ancestor and a reparse-point "
          "leaf",
          "[privacy_permissions][win_internals]") {
    HiveDir hd;
    const fs::path real = hd.dir / "real";
    fs::create_directory(real);
    { std::ofstream(real / "hive.bin", std::ios::binary) << "regf"; }
    const fs::path link = hd.dir / "link";
    const fs::path file_link = hd.dir / "hive-link.bin";
    std::error_code ec;
    fs::create_directory_symlink(real, link, ec);
    if (ec)
        SKIP("a symlink needs SeCreateSymbolicLinkPrivilege or Developer Mode: " << ec.message());
    fs::create_symlink(hd.file, file_link, ec);
    REQUIRE_FALSE(ec);
    const std::string sid = own_sid_string();

    SECTION("a directory symlink anywhere on the path is a reparse ancestor") {
        win::RetentionBudget budget;
        HiveFileGuard guard{budget, sid, 0, std::nullopt};
        CHECK(guard.before_load((link / "hive.bin").wstring()) == "hive_path_reparse_ancestor");
    }
    SECTION("a directory symlink as the leaf is a reparse point") {
        win::RetentionBudget budget;
        HiveFileGuard guard{budget, sid, 0, std::nullopt};
        CHECK(guard.before_load(link.wstring()) == "hive_reparse_point");
    }
    SECTION("a file symlink as the leaf is a reparse point") {
        win::RetentionBudget budget;
        HiveFileGuard guard{budget, sid, 0, std::nullopt};
        CHECK(guard.before_load(file_link.wstring()) == "hive_reparse_point");
    }
}

TEST_CASE("privacy_permissions win: HiveFileGuard refuses a hive file over the size cap",
          "[privacy_permissions][win_internals]") {
    HiveDir hd;
    {
        const UniqueHandle h{CreateFileW(hd.file.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                                         FILE_ATTRIBUTE_NORMAL, nullptr)};
        REQUIRE(h.ok());
        DWORD ret = 0;
        if (!DeviceIoControl(h.h, FSCTL_SET_SPARSE, nullptr, 0, nullptr, 0, &ret, nullptr))
            SKIP("the temp volume cannot hold a sparse file (win32 " << GetLastError() << ")");
        LARGE_INTEGER end;
        end.QuadPart = static_cast<LONGLONG>(win::kMaxHiveBytes) + 1; // sparse: no disk consumed
        REQUIRE(SetFilePointerEx(h.h, end, nullptr, FILE_BEGIN));
        REQUIRE(SetEndOfFile(h.h));
    }
    win::RetentionBudget budget;
    HiveFileGuard guard{budget, own_sid_string(), 0, std::nullopt};
    CHECK(guard.before_load(hd.file.wstring()) == "hive_oversized");
}

TEST_CASE("privacy_permissions win: HiveFileGuard refuses a reparse-point or hard-linked sidecar "
          "and an over-cap sidecar count, and accepts a regular one",
          "[privacy_permissions][win_internals]") {
    HiveDir hd;
    const std::string sid = own_sid_string();
    const fs::path log1 = hd.dir / "hive.bin.LOG1"; // `<hive file name>.LOG1`, as the kernel names it
    win::RetentionBudget budget;
    HiveFileGuard guard{budget, sid, 0, std::nullopt};

    SECTION("a regular sidecar is what the kernel creates: accepted") {
        { std::ofstream(log1, std::ios::binary) << "log"; }
        CHECK(guard.before_load(hd.file.wstring()) == "");
    }
    SECTION("a hard-linked sidecar is refused") {
        if (!CreateHardLinkW(log1.c_str(), hd.file.c_str(), nullptr))
            SKIP("the temp volume cannot hard-link (win32 " << GetLastError() << ")");
        CHECK(guard.before_load(hd.file.wstring()) == "hive_sidecar_hardlinked");
    }
    SECTION("a dangling symlink sidecar is refused and its target is never created") {
        const fs::path target = hd.dir / "dangling.bin";
        std::error_code ec;
        fs::create_symlink(target, log1, ec);
        if (ec)
            SKIP("a symlink needs SeCreateSymbolicLinkPrivilege or Developer Mode: " << ec.message());
        CHECK(guard.before_load(hd.file.wstring()) == "hive_sidecar_reparse");
        CHECK_FALSE(fs::exists(target));
    }
    SECTION("more than kMaxHiveSidecars sidecar-named entries are refused") {
        for (std::size_t i = 0; i <= win::kMaxHiveSidecars; ++i)
            std::ofstream(hd.dir / ("hive.bin.LOG" + std::to_string(i)), std::ios::binary) << "log";
        CHECK(guard.before_load(hd.file.wstring()) == "hive_sidecar_count");
    }
}

TEST_CASE("privacy_permissions win: HiveFileGuard reads the owner from the file, not the profile",
          "[privacy_permissions][win_internals]") {
    HiveDir hd;
    // SeRestorePrivilege lets the fixture assign an owner outside the allow-set (S-1-5-19), so the
    // refusal is asserted unconditionally under any identity (LocalSystem owns files as S-1-5-18,
    // an allow-set owner, which would make a "natural owner" assertion vacuous).
    const yuzu::win::PrivilegeScope restore(L"SeRestorePrivilege");
    if (!restore.ok()) SKIP("assigning a foreign owner needs SeRestorePrivilege: not held here");
    PSID foreign = nullptr;
    REQUIRE(ConvertStringSidToSidW(L"S-1-5-19", &foreign));
    const LocalFreeGuard foreign_guard{foreign};
    std::wstring wfile = hd.file.wstring();
    if (const DWORD rc = SetNamedSecurityInfoW(wfile.data(), SE_FILE_OBJECT,
                                               OWNER_SECURITY_INFORMATION, foreign, nullptr,
                                               nullptr, nullptr);
        rc != ERROR_SUCCESS)
        SKIP("cannot set the fixture file's owner to S-1-5-19 (win32 " << rc << ")");
    win::RetentionBudget budget;
    HiveFileGuard guard{budget, synthetic_sid(), 0, std::nullopt};
    CHECK(guard.before_load(hd.file.wstring()) == "hive_owner_unexpected");
}

TEST_CASE("privacy_permissions win: with_user_hive reads a loaded HKU hive first and never enters "
          "the offline arm",
          "[privacy_permissions][win_internals]") {
    const std::string sid = own_sid_string();
    {
        yuzu::win::RegKey own;
        if (RegOpenKeyExW(HKEY_USERS, yuzu::win::to_wide(sid).c_str(), 0, KEY_READ, own.put()) !=
            ERROR_SUCCESS)
            SKIP("premise: the test process's own user hive is loaded under HKEY_USERS\\<its SID>; "
                 "this host's is not, so the live-first branch cannot be exercised");
    }
    int before_calls = 0, after_calls = 0, fn_calls = 0;
    const yuzu::win::OfflineHiveFileCheck check{
        [&](const std::wstring&) {
            ++before_calls;
            return std::string{"must_not_run"};
        },
        [&](const std::wstring&) {
            ++after_calls;
            return std::string{"must_not_run"};
        }};
    yuzu::win::HiveAccessReport report;
    // The profile path is deliberately bogus: if the live branch were skipped, the offline arm
    // would be entered (and refused by the first hook, or by a missing privilege) instead.
    const auto status = yuzu::win::with_user_hive(
        sid, "C:\\yuzu_bogus_profile_path",
        [&](HKEY root) {
            ++fn_calls;
            CHECK(root != nullptr);
        },
        &report, &check);
    CHECK(status == yuzu::win::HiveAccessStatus::ok);
    CHECK(fn_calls == 1);
    CHECK(before_calls == 0);
    CHECK(after_calls == 0);
    CHECK_FALSE(report.mounted_offline);
}

namespace {

/// What the file-check hooks saw, and what with_user_hive did with them.
struct HookCounts {
    int before = 0, after = 0, fn = 0;
};

/// Drives the PRODUCTION with_user_hive for the synthetic SID (no live hive, so the offline arm)
/// with hooks that return the given tokens ("" = proceed).
yuzu::win::HiveAccessStatus run_offline(const std::string& profile_path, const std::string& before,
                                        const std::string& after, HookCounts& n,
                                        yuzu::win::HiveAccessReport& report) {
    const yuzu::win::OfflineHiveFileCheck check{[&](const std::wstring&) {
                                                    ++n.before;
                                                    return before;
                                                },
                                                [&](const std::wstring&) {
                                                    ++n.after;
                                                    return after;
                                                }};
    return yuzu::win::with_user_hive(synthetic_sid(), profile_path, [&](HKEY) { ++n.fn; }, &report,
                                     &check);
}

void require_live_arm_missed() {
    yuzu::win::RegKey live;
    REQUIRE(RegOpenKeyExW(HKEY_USERS, yuzu::win::to_wide(synthetic_sid()).c_str(), 0, KEY_READ,
                          live.put()) != ERROR_SUCCESS);
}

} // namespace

TEST_CASE("privacy_permissions win: with_user_hive refuses on a before_load token with nothing "
          "mounted and no mount reported",
          "[privacy_permissions][win_internals]") {
    require_live_arm_missed();
    HookCounts n;
    yuzu::win::HiveAccessReport report;
    const auto status = run_offline("C:\\yuzu_bogus_profile_path", "forced_before", "", n, report);
    if (status == yuzu::win::HiveAccessStatus::privilege_missing)
        SKIP("the offline arm needs SeBackupPrivilege and SeRestorePrivilege: not held here");
    CHECK(status == yuzu::win::HiveAccessStatus::file_refused);
    CHECK(report.refusal == "forced_before");
    CHECK(n.before == 1);
    CHECK(n.after == 0);
    CHECK(n.fn == 0);
    CHECK_FALSE(report.mounted_offline); // no mount was attempted
    CHECK(report.mount_name.empty());
    CHECK_FALSE(synthetic_mount_present());
}

TEST_CASE("privacy_permissions win: with_user_hive refuses on an after_load token without calling "
          "fn, and still unloads the mount",
          "[privacy_permissions][win_internals]") {
    require_live_arm_missed();
    TestKey saved(false); // RegSaveKeyExW saves only non-volatile keys
    set_sz(saved.make(L"k").get(), L"v", L"1");
    yuzu::test::TempDir tmp("yuzu_test_privperm_hive_");
    fs::create_directories(tmp.path);
    {
        const yuzu::win::PrivilegeScope backup(L"SeBackupPrivilege");
        if (!backup.ok()) SKIP("saving a mountable hive needs SeBackupPrivilege: not held here");
        const LONG rc = RegSaveKeyExW(saved.root, (tmp.path / "NTUSER.DAT").c_str(), nullptr,
                                      REG_LATEST_FORMAT);
        if (rc == ERROR_PRIVILEGE_NOT_HELD) SKIP("RegSaveKeyExW: privilege not held");
        REQUIRE(rc == ERROR_SUCCESS);
    }
    const std::string profile = yuzu::win::from_wide(tmp.path.c_str());

    yuzu::win::RegKey no_held; // nothing holds either mount's root here
    HookCounts control;
    yuzu::win::HiveAccessReport control_report;
    const HiveCleanup control_cleanup{no_held, control_report};
    const auto ok = run_offline(profile, "", "", control, control_report);
    if (ok == yuzu::win::HiveAccessStatus::privilege_missing)
        SKIP("the offline arm needs SeBackupPrivilege and SeRestorePrivilege: not held here");
    // Control: the saved hive mounts, the accepting hooks let fn run, and the unload is clean.
    CHECK(ok == yuzu::win::HiveAccessStatus::ok);
    CHECK(control.fn == 1);
    CHECK_FALSE(control_report.unload_failed);

    HookCounts n;
    yuzu::win::HiveAccessReport report;
    const HiveCleanup cleanup{no_held, report};
    const auto status = run_offline(profile, "", "forced_after", n, report);
    CHECK(status == yuzu::win::HiveAccessStatus::file_refused);
    CHECK(report.refusal == "forced_after");
    CHECK(n.before == 1);
    CHECK(n.after == 1);
    CHECK(n.fn == 0);
    CHECK(report.mounted_offline);
    CHECK_FALSE(report.mount_name.empty());
    CHECK_FALSE(report.unload_failed);
    CHECK_FALSE(synthetic_mount_present()); // the refusal fell through to the unload
}

TEST_CASE("privacy_permissions win: with_user_hive reports a failed unload even when fn throws",
          "[privacy_permissions][win_internals]") {
    // Real RegSaveKeyExW/RegLoadKeyW (privilege-gated, SKIP otherwise): the destructor path under
    // test only exists when a genuine mount cannot unload, which no fake registry can reach.
    require_live_arm_missed();
    TestKey saved(false); // RegSaveKeyExW saves only non-volatile keys
    set_sz(saved.make(L"k").get(), L"v", L"1");
    yuzu::test::TempDir tmp("yuzu_test_privperm_hive_");
    fs::create_directories(tmp.path);
    {
        const yuzu::win::PrivilegeScope backup(L"SeBackupPrivilege");
        if (!backup.ok()) SKIP("saving a mountable hive needs SeBackupPrivilege: not held here");
        const LONG rc = RegSaveKeyExW(saved.root, (tmp.path / "NTUSER.DAT").c_str(), nullptr,
                                      REG_LATEST_FORMAT);
        if (rc == ERROR_PRIVILEGE_NOT_HELD) SKIP("RegSaveKeyExW: privilege not held");
        REQUIRE(rc == ERROR_SUCCESS);
    }
    const std::string profile = yuzu::win::from_wide(tmp.path.c_str());

    // Declared outside the call so the handle outlives with_root's root: the mount cannot unload.
    // (The fixture's child `k` is volatile and so is not saved into the hive: hold the ROOT.)
    yuzu::win::RegKey held;
    yuzu::win::HiveAccessReport report;
    const HiveCleanup cleanup{held, report};

    bool threw = false;
    try {
        yuzu::win::with_user_hive(
            synthetic_sid(), profile,
            [&](HKEY root) {
                RegOpenKeyExW(root, nullptr, 0, KEY_READ, held.put());
                throw std::runtime_error("fn failed");
            },
            &report);
    } catch (const std::runtime_error&) {
        threw = true;
    }
    if (!threw && !report.mounted_offline)
        SKIP("the offline arm needs SeBackupPrivilege and SeRestorePrivilege: not held here");
    CHECK(threw);
    CHECK(report.mounted_offline);
    CHECK_FALSE(report.mount_name.empty());
    CHECK(report.unload_failed); // written by the guard's destructor while unwinding
    cleanup.run();
    CHECK_FALSE(synthetic_mount_present());
}

TEST_CASE("privacy_permissions win: final_path_matches is the ordinal case-insensitive comparison "
          "the file system uses, with the \\\\?\\ prefix required",
          "[privacy_permissions][win_internals]") {
    const std::wstring requested = L"C:\\Users\\\u00C4nne\\NTUSER.DAT"; // capital A-diaeresis
    SECTION("a non-ASCII case-only difference is the same path") {
        CHECK(final_path_matches(requested, L"\\\\?\\C:\\Users\\\u00E4nne\\NTUSER.DAT"));
    }
    SECTION("an ASCII case-only difference is the same path") {
        CHECK(final_path_matches(L"C:\\Users\\jsmith\\NTUSER.DAT",
                                 L"\\\\?\\c:\\USERS\\JSmith\\ntuser.dat"));
    }
    SECTION("a doubled separator in the requested path is the same path") {
        CHECK(final_path_matches(L"C:\\Users\\jsmith\\\\NTUSER.DAT",
                                 L"\\\\?\\C:\\Users\\jsmith\\NTUSER.DAT"));
    }
    SECTION("a different name is a different path") {
        CHECK_FALSE(final_path_matches(requested, L"\\\\?\\C:\\Users\\Anne\\NTUSER.DAT"));
    }
    SECTION("a different drive is a different path") {
        CHECK_FALSE(final_path_matches(requested, L"\\\\?\\D:\\Users\\\u00C4nne\\NTUSER.DAT"));
    }
    SECTION("a final path without the \\\\?\\ prefix is not the requested path") {
        CHECK_FALSE(final_path_matches(requested, requested));
    }
}

#endif // defined(_WIN32)
