/**
 * test_installed_apps_registry_walk.cpp -- #4711 hive-read status contract.
 *
 * Drives the plugin's ACTUAL walk (installed_apps_registry_walk.hpp) against an
 * isolated, process-suffixed scratch key under HKCU. Pins: an ok walk, an
 * absent root (benign only when the root says so), a failed root, and the
 * mixed case -- a partially failed walk keeps the apps it read AND reports
 * degraded, so list_inventory can reject the cycle instead of publishing a
 * partial set as complete.
 *
 * The walker's per-entry branches (child-open denial, a child that vanished,
 * an enumeration error after a good entry, ERROR_MORE_DATA then another entry)
 * run against a scripted FakeOps injected through the walk's registry-call seam,
 * and the production list_inventory path (reg_walk::list_inventory, the body the
 * plugin's do_list_inventory runs on Windows) is driven end to end: a degraded
 * walk must yield rc 1, NO rows, and CONSTRAINED/PARTIAL
 * installed_apps:acquisition_degraded.
 *
 * TEST-EFFICIENCY: registry reads under one isolated key plus in-memory fakes;
 * no subprocess, no timing assumptions.
 *
 * Windows-only; the walk does not exist elsewhere.
 */

#include <catch2/catch_test_macros.hpp>

#ifdef _WIN32

#include <cstdint>
#include <cstring>
#include <cwchar>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include <win_reg_handle.hpp>

#include "installed_apps_registry_walk.hpp"

namespace {

namespace rw = yuzu::installed_apps::reg_walk;
using yuzu::installed_apps::parsers::HiveRead;

// Same isolation idiom as test_installed_apps_registry_utf8.cpp: process-suffixed
// leaf, single HKEY owner, never a fixed key name.
struct ScratchKey {
    std::wstring sub;
    HKEY key{};
    bool ok{false};
    ScratchKey()
        : sub(L"SOFTWARE\\YuzuTest\\InstalledAppsWalk_" + std::to_wstring(GetCurrentProcessId())) {
        ok = RegCreateKeyExW(HKEY_CURRENT_USER, sub.c_str(), 0, nullptr, 0, KEY_READ | KEY_WRITE,
                             nullptr, &key, nullptr) == ERROR_SUCCESS;
    }
    ~ScratchKey() {
        if (key)
            RegCloseKey(key);
        RegDeleteKeyW(HKEY_CURRENT_USER, (sub + L"\\Uninstall\\AppA").c_str());
        RegDeleteKeyW(HKEY_CURRENT_USER, (sub + L"\\Uninstall\\NoName").c_str());
        RegDeleteKeyW(HKEY_CURRENT_USER, (sub + L"\\Uninstall").c_str());
        RegDeleteKeyW(HKEY_CURRENT_USER, sub.c_str());
    }
    ScratchKey(const ScratchKey&) = delete;
    ScratchKey& operator=(const ScratchKey&) = delete;
    ScratchKey(ScratchKey&&) = delete;
    ScratchKey& operator=(ScratchKey&&) = delete;
};

void set_sz(HKEY key, const wchar_t* name, const wchar_t* value) {
    const DWORD bytes = static_cast<DWORD>((wcslen(value) + 1) * sizeof(wchar_t));
    REQUIRE(RegSetValueExW(key, name, 0, REG_SZ, reinterpret_cast<const BYTE*>(value), bytes) ==
            ERROR_SUCCESS);
}

HKEY create_sub(HKEY parent, const std::wstring& path) {
    HKEY k{};
    REQUIRE(RegCreateKeyExW(parent, path.c_str(), 0, nullptr, 0, KEY_READ | KEY_WRITE, nullptr, &k,
                            nullptr) == ERROR_SUCCESS);
    return k;
}

// Plant Uninstall\AppA (full) and Uninstall\NoName (no DisplayName).
void plant(const ScratchKey& scratch) {
    yuzu::win::RegKey a{create_sub(HKEY_CURRENT_USER, scratch.sub + L"\\Uninstall\\AppA")};
    set_sz(a.get(), L"DisplayName", L"AppA");
    set_sz(a.get(), L"DisplayVersion", L"1.2.3");
    set_sz(a.get(), L"Publisher", L"Acme");
    set_sz(a.get(), L"InstallLocation", L"C:\\Program Files\\AppA");
    yuzu::win::RegKey no_name{create_sub(HKEY_CURRENT_USER, scratch.sub + L"\\Uninstall\\NoName")};
}

// ── Scripted registry: drives the walker's own branches, deterministically ──
// Handles are small fake integers; every open is tracked so a test also proves the
// walker closes exactly what it opened (never RegCloseKey on a fake).
struct FakeEntry {
    LSTATUS enum_rc = ERROR_SUCCESS; // status RegEnumKeyExW returns at this index
    std::wstring name;
    LSTATUS open_rc = ERROR_SUCCESS; // status opening this entry's key returns
    std::map<std::string, std::string> values;
};

HKEY fake_handle(std::uintptr_t n) {
    return reinterpret_cast<HKEY>(n);
}
const HKEY kFakeRoot = fake_handle(0x10);  // a root that opens
const HKEY kDeniedRoot = fake_handle(0x11); // a root whose open is denied
constexpr std::uintptr_t kHiveHandle = 0x20;
constexpr std::uintptr_t kChildBase = 0x100;

struct FakeOps {
    std::vector<FakeEntry> entries;
    mutable std::set<std::uintptr_t> open_handles;

    LSTATUS open(HKEY parent, const wchar_t* sub, REGSAM, HKEY* out) const {
        if (parent == kDeniedRoot)
            return ERROR_ACCESS_DENIED;
        if (parent == kFakeRoot) {
            *out = fake_handle(kHiveHandle);
            open_handles.insert(kHiveHandle);
            return ERROR_SUCCESS;
        }
        for (std::size_t i = 0; i < entries.size(); ++i) {
            if (entries[i].name != sub)
                continue;
            if (entries[i].open_rc != ERROR_SUCCESS)
                return entries[i].open_rc;
            *out = fake_handle(kChildBase + i);
            open_handles.insert(kChildBase + i);
            return ERROR_SUCCESS;
        }
        return ERROR_FILE_NOT_FOUND;
    }
    LSTATUS enum_key(HKEY, DWORD idx, wchar_t* name, DWORD* name_len) const {
        if (idx >= entries.size())
            return ERROR_NO_MORE_ITEMS;
        const auto& e = entries[idx];
        if (e.enum_rc != ERROR_SUCCESS)
            return e.enum_rc;
        wcscpy_s(name, *name_len, e.name.c_str());
        *name_len = static_cast<DWORD>(e.name.size());
        return ERROR_SUCCESS;
    }
    void close(HKEY h) const { open_handles.erase(reinterpret_cast<std::uintptr_t>(h)); }
    std::string read_str(HKEY h, const char* value_name, bool) const {
        const auto idx = reinterpret_cast<std::uintptr_t>(h) - kChildBase;
        const auto it = entries[idx].values.find(value_name);
        return it == entries[idx].values.end() ? std::string{} : it->second;
    }
};

FakeEntry app(const char* name) {
    return FakeEntry{.name = std::wstring(name, name + std::strlen(name)),
                     .values = {{"DisplayName", name}}};
}
FakeEntry denied(const char* name) {
    FakeEntry e = app(name);
    e.open_rc = ERROR_ACCESS_DENIED;
    return e;
}
FakeEntry enum_fails(LSTATUS rc) {
    return FakeEntry{.enum_rc = rc};
}

const rw::UninstallRoot kOkRoot{kFakeRoot, L"Uninstall", 0, false};

// Records what the plugin's action reports to the agent.
struct FakeCtx {
    struct Status {
        YuzuResultStatus status;
        YuzuResultCompleteness completeness;
        std::string provenance;
    };
    std::vector<std::string> lines;
    std::vector<Status> statuses;
    void write_output(std::string_view l) { lines.emplace_back(l); }
    void set_result_status(YuzuResultStatus s, YuzuResultCompleteness c,
                           std::string_view p = {}) {
        statuses.push_back({s, c, std::string{p}});
    }
};

std::vector<std::string> names(const std::vector<rw::AppInfo>& apps) {
    std::vector<std::string> n;
    for (const auto& a : apps)
        n.push_back(a.name);
    return n;
}

} // namespace

TEST_CASE("installed_apps registry walk: ok root yields the named app, not degraded",
          "[installed_apps][registry][windows]") {
    ScratchKey scratch;
    REQUIRE(scratch.ok);
    plant(scratch);
    const rw::UninstallRoot roots[] = {{HKEY_CURRENT_USER, scratch.sub + L"\\Uninstall", 0, true}};
    const auto res = rw::collect_uninstall_apps(roots);
    CHECK_FALSE(res.degraded);
    REQUIRE(res.apps.size() == 1);
    CHECK(res.apps[0].name == "AppA");
    CHECK(res.apps[0].version == "1.2.3");
    CHECK(res.apps[0].publisher == "Acme");
    REQUIRE(res.apps[0].install_location.size() >= 2);
    CHECK(res.apps[0].install_location[1] == ':');
}

TEST_CASE("installed_apps registry walk: a missing root is absent only when absent_ok",
          "[installed_apps][registry][windows]") {
    ScratchKey scratch;
    REQUIRE(scratch.ok);
    const std::wstring missing = scratch.sub + L"\\Missing";
    std::vector<rw::AppInfo> apps;

    const rw::UninstallRoot ok_root{HKEY_CURRENT_USER, missing, 0, true};
    CHECK(rw::enumerate_uninstall_key(ok_root, apps) == HiveRead::absent);
    const rw::UninstallRoot ok_roots[] = {ok_root};
    CHECK_FALSE(rw::collect_uninstall_apps(ok_roots).degraded);

    const rw::UninstallRoot bad_root{HKEY_CURRENT_USER, missing, 0, false};
    CHECK(rw::enumerate_uninstall_key(bad_root, apps) == HiveRead::failed);
    const rw::UninstallRoot bad_roots[] = {bad_root};
    CHECK(rw::collect_uninstall_apps(bad_roots).degraded);
}

TEST_CASE("installed_apps registry walk: a failed root keeps the other roots' apps AND degrades",
          "[installed_apps][registry][windows]") {
    ScratchKey scratch;
    REQUIRE(scratch.ok);
    plant(scratch);
    // 0x1 is never a valid handle: RegOpenKeyExW fails with a status that is not
    // FILE_NOT_FOUND. The contract pinned is "degraded", not the exact LSTATUS.
    const rw::UninstallRoot roots[] = {
        {HKEY_CURRENT_USER, scratch.sub + L"\\Uninstall", 0, true},
        {reinterpret_cast<HKEY>(static_cast<std::intptr_t>(0x1)), L"Uninstall", 0, false},
    };
    const auto res = rw::collect_uninstall_apps(roots);
    CHECK(res.degraded);
    REQUIRE(res.failed_roots.size() == 1);
    CHECK(res.failed_roots[0] == 1);
    REQUIRE(res.apps.size() == 1);
    CHECK(res.apps[0].name == "AppA");
}

TEST_CASE("walk: a denied child key degrades the walk but keeps the entries that opened",
          "[installed_apps][registry][windows]") {
    FakeOps ops{{app("AppA"), denied("AppB"), app("AppC")}};
    std::vector<rw::AppInfo> apps;
    CHECK(rw::enumerate_uninstall_key(kOkRoot, apps, ops) == HiveRead::failed);
    CHECK(names(apps) == std::vector<std::string>{"AppA", "AppC"});
    CHECK(ops.open_handles.empty());
}

TEST_CASE("walk: a child that vanished between enumerate and open is benign",
          "[installed_apps][registry][windows]") {
    FakeEntry gone = app("AppB");
    gone.open_rc = ERROR_FILE_NOT_FOUND;
    FakeOps ops{{app("AppA"), gone}};
    std::vector<rw::AppInfo> apps;
    CHECK(rw::enumerate_uninstall_key(kOkRoot, apps, ops) == HiveRead::ok);
    CHECK(names(apps) == std::vector<std::string>{"AppA"});
    CHECK(ops.open_handles.empty());
}

TEST_CASE("walk: an enumeration error after a good entry degrades and stops",
          "[installed_apps][registry][windows]") {
    FakeOps ops{{app("AppA"), enum_fails(ERROR_GEN_FAILURE), app("AppC")}};
    std::vector<rw::AppInfo> apps;
    CHECK(rw::enumerate_uninstall_key(kOkRoot, apps, ops) == HiveRead::failed);
    CHECK(names(apps) == std::vector<std::string>{"AppA"}); // AppC is never reached
    CHECK(ops.open_handles.empty());
}

TEST_CASE("walk: ERROR_MORE_DATA on one name skips it, degrades, and continues",
          "[installed_apps][registry][windows]") {
    FakeOps ops{{app("AppA"), enum_fails(ERROR_MORE_DATA), app("AppC")}};
    std::vector<rw::AppInfo> apps;
    CHECK(rw::enumerate_uninstall_key(kOkRoot, apps, ops) == HiveRead::failed);
    CHECK(names(apps) == std::vector<std::string>{"AppA", "AppC"});
    CHECK(ops.open_handles.empty());
}

TEST_CASE("list_inventory: a healthy walk emits inv rows, rc 0, no status",
          "[installed_apps][registry][windows]") {
    FakeOps ops{{app("AppA")}};
    FakeCtx ctx;
    const rw::UninstallRoot roots[] = {kOkRoot};
    CHECK(rw::list_inventory(ctx, roots, ops, [](std::size_t) {}) == 0);
    REQUIRE(ctx.lines.size() == 1);
    CHECK(ctx.lines[0].rfind("inv|AppA|", 0) == 0);
    CHECK(ctx.statuses.empty());
}

TEST_CASE("list_inventory: a failed root yields rc 1, no rows, CONSTRAINED/PARTIAL",
          "[installed_apps][registry][windows]") {
    // The mixed case at the production seam: root 0 reads AppA, root 1 is denied.
    FakeOps ops{{app("AppA")}};
    FakeCtx ctx;
    std::vector<std::size_t> failed;
    const rw::UninstallRoot roots[] = {kOkRoot, {kDeniedRoot, L"Uninstall", 0, false}};
    CHECK(rw::list_inventory(ctx, roots, ops, [&](std::size_t i) { failed.push_back(i); }) == 1);
    CHECK(ctx.lines.empty()); // never a partial snapshot as authoritative
    REQUIRE(ctx.statuses.size() == 1);
    CHECK(ctx.statuses[0].status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(ctx.statuses[0].completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(ctx.statuses[0].provenance == "installed_apps:acquisition_degraded");
    CHECK(failed == std::vector<std::size_t>{1});
}

TEST_CASE("list_inventory: a denied child key alone yields rc 1 and no rows",
          "[installed_apps][registry][windows]") {
    FakeOps ops{{app("AppA"), denied("AppB")}};
    FakeCtx ctx;
    const rw::UninstallRoot roots[] = {kOkRoot};
    CHECK(rw::list_inventory(ctx, roots, ops, [](std::size_t) {}) == 1);
    CHECK(ctx.lines.empty());
    REQUIRE(ctx.statuses.size() == 1);
    CHECK(ctx.statuses[0].provenance == "installed_apps:acquisition_degraded");
}

#endif // _WIN32
