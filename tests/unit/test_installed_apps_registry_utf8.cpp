/**
 * test_installed_apps_registry_utf8.cpp -- #1662 regression guard.
 *
 * The installed_apps plugin must read REG_SZ uninstall-key values as UTF-8.
 * Before #1679 it used the ANSI registry APIs (RegQueryValueExA), which return
 * the system code page (cp1252 on Western Windows), so the downstream
 * sanitize_utf8 scrub turned every non-ASCII byte into '?' ("Cafe<acute>" ->
 * "Caf?"), corrupting the typed software-inventory store and breaking its
 * exact-match `WHERE name=$1` lookups.
 *
 * This test exercises the plugin's ACTUAL conversion (reg_sz_to_utf8 from
 * installed_apps_registry_utf8.hpp -- the same header the plugin includes, not a
 * re-implementation) against the real Windows registry: it stores genuine UTF-16
 * REG_SZ values under a scratch HKCU key, reads them back through the plugin's
 * read path, and asserts correct UTF-8. Because it calls the shared helper, a
 * plugin regression in that helper is caught here.
 *
 * It deliberately asserts ONLY the fix's guarantee (W path -> correct UTF-8),
 * which holds regardless of the host ANSI code page, so it can't flake on a
 * runner with the "Use Unicode UTF-8 for worldwide language support" beta
 * enabled (GetACP()==CP_UTF8).
 *
 * Source is pure ASCII (\u / \U escapes in wide literals, \x bytes in the
 * expected UTF-8) so it does not depend on the MSVC /utf-8 flag or source code
 * page.
 *
 * Windows-only; the plugin's registry code is a no-op elsewhere. Uses a scratch
 * HKCU key the running user can always create/write, mirroring
 * test_guard_registry.cpp.
 */

#include <catch2/catch_test_macros.hpp>

#include <string>

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cwchar> // wcslen (do not rely on transitive <windows.h> inclusion)

#include "installed_apps_registry_utf8.hpp"

namespace {

using yuzu::installed_apps::reg_utf8::read_reg_string;

// RAII owner of a scratch key under the shared SOFTWARE\YuzuTest namespace (same
// convention as test_guard_registry.cpp). The leaf is suffixed with the process
// id so two concurrent test processes running as the same user never share a key
// (the registry analog of unique_temp_path -- avoids the #473/#482 fixed-path
// flake class). Non-copyable/non-movable so the single-HKEY-owner contract is
// enforced, not assumed (a copy would double-close/double-delete the same HKEY)
// -- matches the HKeyCloser idiom in installed_apps_plugin.cpp.
struct ScratchKey {
    std::wstring sub;
    HKEY key{};
    bool ok{false};
    ScratchKey()
        : sub(L"SOFTWARE\\YuzuTest\\InstalledAppsUtf8_" +
              std::to_wstring(GetCurrentProcessId())) {
        ok = RegCreateKeyExW(HKEY_CURRENT_USER, sub.c_str(), 0, nullptr, 0, KEY_READ | KEY_WRITE,
                             nullptr, &key, nullptr) == ERROR_SUCCESS;
    }
    ~ScratchKey() {
        if (key) {
            RegCloseKey(key);
        }
        RegDeleteKeyW(HKEY_CURRENT_USER, sub.c_str());
    }
    ScratchKey(const ScratchKey&) = delete;
    ScratchKey& operator=(const ScratchKey&) = delete;
    ScratchKey(ScratchKey&&) = delete;
    ScratchKey& operator=(ScratchKey&&) = delete;
};

// Store a genuine UTF-16 REG_SZ value (the way Windows actually persists names).
void set_sz(HKEY key, const wchar_t* name, const wchar_t* value) {
    DWORD bytes = static_cast<DWORD>((wcslen(value) + 1) * sizeof(wchar_t));
    REQUIRE(RegSetValueExW(key, name, 0, REG_SZ, reinterpret_cast<const BYTE*>(value), bytes) ==
            ERROR_SUCCESS);
}

void set_expand_sz(HKEY key, const wchar_t* name, const wchar_t* value) {
    DWORD bytes = static_cast<DWORD>((wcslen(value) + 1) * sizeof(wchar_t));
    REQUIRE(RegSetValueExW(key, name, 0, REG_EXPAND_SZ, reinterpret_cast<const BYTE*>(value),
                           bytes) == ERROR_SUCCESS);
}

void set_dword(HKEY key, const wchar_t* name, DWORD value) {
    REQUIRE(RegSetValueExW(key, name, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&value),
                           sizeof(value)) == ERROR_SUCCESS);
}

} // namespace

TEST_CASE("installed_apps #1662: non-ASCII REG_SZ round-trips as correct UTF-8",
          "[installed_apps][registry][utf8][windows]") {
    ScratchKey scratch;
    REQUIRE(scratch.ok);

    INFO("system ANSI code page (GetACP) = " << GetACP());

    struct Case {
        const char* name;          // ASCII: the value name read_reg_string takes, and INFO
                                   // (streaming wchar_t* into a narrow ostream is a deleted
                                   // operator in C++20+)
        const wchar_t* wide_name;  // the same name for set_sz
        const wchar_t* wide;       // stored UTF-16 (\u/\U escapes -> code-page independent)
        std::string expected_utf8; // correct UTF-8 the fix must produce (\x bytes)
    };
    const Case cases[] = {
        // "Cafe<U+00E9> Manager" (Latin-1)
        {"DisplayName", L"DisplayName", L"Caf\u00E9 Manager", std::string("Caf\xC3\xA9 Manager")},
        // "M<U+00FC>nchen GmbH" (Latin-1)
        {"Publisher", L"Publisher", L"M\u00FCnchen GmbH", std::string("M\xC3\xBCnchen GmbH")},
        // Cyrillic "Kasperskiy" -- non-Latin, multi-byte UTF-8 throughout.
        {"DisplayNameCyr", L"DisplayNameCyr", L"\u041A\u0430\u0441\u043F\u0435\u0440\u0441\u043A\u0438\u0439",
         std::string("\xD0\x9A\xD0\xB0\xD1\x81\xD0\xBF\xD0\xB5\xD1\x80\xD1\x81\xD0\xBA\xD0\xB8\xD0"
                     "\xB9")},
        // Supplementary plane U+1F600 (grinning face): a UTF-16 surrogate pair
        // (two wchar_t) -> a 4-byte UTF-8 sequence. Guards the surrogate path.
        {"Emoji", L"Emoji", L"\U0001F600", std::string("\xF0\x9F\x98\x80")},
    };

    for (const auto& c : cases) {
        set_sz(scratch.key, c.wide_name, c.wide);
        const std::string got = read_reg_string(scratch.key, c.name, false);
        INFO("value " << c.name);
        CHECK(got == c.expected_utf8);
    }
}

TEST_CASE("installed_apps #1662: a trailing-NUL-free REG_SZ is not truncated",
          "[installed_apps][registry][utf8][windows]") {
    // RegSetValueExW with a byte count that excludes the terminating NUL is a
    // legitimate REG_SZ; the length-aware conversion must still return the whole
    // string (the pre-fix `std::string(buf, size-1)` shape assumed a NUL).
    ScratchKey scratch;
    REQUIRE(scratch.ok);

    const wchar_t* value = L"Caf\u00E9"; // "Cafe<U+00E9>"
    DWORD bytes_no_nul = static_cast<DWORD>(wcslen(value) * sizeof(wchar_t)); // no NUL
    REQUIRE(RegSetValueExW(scratch.key, L"NoNul", 0, REG_SZ,
                           reinterpret_cast<const BYTE*>(value), bytes_no_nul) == ERROR_SUCCESS);

    CHECK(read_reg_string(scratch.key, "NoNul", false) == std::string("Caf\xC3\xA9"));
}

TEST_CASE("installed_apps #1662: an empty REG_SZ reads back as empty",
          "[installed_apps][registry][utf8][windows]") {
    // A lone-NUL REG_SZ (size == sizeof(wchar_t)) must convert to "" without
    // underflowing the NUL-trim/length math.
    ScratchKey scratch;
    REQUIRE(scratch.ok);
    set_sz(scratch.key, L"Empty", L"");
    CHECK(read_reg_string(scratch.key, "Empty", false).empty());
}

TEST_CASE("installed_apps read_reg_string: REG_EXPAND_SZ is accepted only under the "
          "InstallLocation policy, and returned raw",
          "[installed_apps][registry][windows]") {
    ScratchKey scratch;
    REQUIRE(scratch.ok);
    set_expand_sz(scratch.key, L"InstallLocation", L"%ProgramFiles%\\Yuzu\\");
    CHECK(read_reg_string(scratch.key, "InstallLocation", true) == "%ProgramFiles%\\Yuzu\\");
    // Mutation: ignoring accept_expand_sz (always true) fails this line -- the
    // ADR-0016 hashed fields must never widen to REG_EXPAND_SZ.
    CHECK(read_reg_string(scratch.key, "InstallLocation", false).empty());
}

TEST_CASE("installed_apps read_reg_string: a REG_DWORD reads as empty under either policy",
          "[installed_apps][registry][windows]") {
    ScratchKey scratch;
    REQUIRE(scratch.ok);
    set_dword(scratch.key, L"SystemComponent", 1);
    CHECK(read_reg_string(scratch.key, "SystemComponent", false).empty());
    CHECK(read_reg_string(scratch.key, "SystemComponent", true).empty());
}

TEST_CASE("installed_apps read_reg_string: a value over 511 WCHARs reads as empty, never "
          "truncated (ERROR_MORE_DATA; a larger-buffer retry is a tracked follow-up)",
          "[installed_apps][registry][windows]") {
    ScratchKey scratch;
    REQUIRE(scratch.ok);
    const std::wstring big(600, L'a');
    set_sz(scratch.key, L"Long", big.c_str());
    CHECK(read_reg_string(scratch.key, "Long", true).empty());
}

#endif // _WIN32
