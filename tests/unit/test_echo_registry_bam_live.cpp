/**
 * test_echo_registry_bam_live.cpp -- the registry source's bam\State exclusion against the REAL
 * registry (#6898). Windows only; the translation unit is empty elsewhere.
 *
 * The exclusion is anchored to HKLM\SYSTEM\CurrentControlSet\Services\bam\State (see
 * registry_path_excluded), so a salted HKLM\SOFTWARE root cannot exercise it; this case watches
 * the real bam key and writes only scratch keys named with registry_scratch_prefix(), which
 * scripts/ci/check-registry-test-leftovers.ps1 scans under both bam roots.
 *
 * is_elevated() and salt() are copies of the helpers in test_echo_registry_source.cpp (anonymous
 * namespace there; not shared because that file is edited by other work in flight). Keep the
 * two in step.
 */

#ifdef _WIN32

#include "echo_registry_parsers.hpp"
#include "echo_registry_source.hpp"
#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <sddl.h>
#include <win_str.hpp>

using namespace yuzu::echo;

namespace {

bool is_elevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;
    TOKEN_ELEVATION e{};
    DWORD len = 0;
    const bool ok = GetTokenInformation(token, TokenElevation, &e, sizeof(e), &len) != 0;
    CloseHandle(token);
    return ok && e.TokenIsElevated != 0;
}

std::string salt() { return std::to_string(::GetCurrentProcessId()) + "_" + std::to_string(::GetTickCount64()); }

// A scratch key below HKLM, deleted (with its contents) on destruction. `deny_all` is set on the
// key through the held handle, which keeps working for writes; the destructor restores access
// through the same handle first so the delete cannot be refused.
struct ScratchKey {
    std::wstring path;
    HKEY h{nullptr};
    bool denied{false};
    explicit ScratchKey(const std::string& below_hklm) : path(yuzu::win::to_wide(below_hklm)) {}
    ScratchKey(const ScratchKey&) = delete;
    ScratchKey& operator=(const ScratchKey&) = delete;
    LONG create() {
        return RegCreateKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, nullptr, 0, KEY_ALL_ACCESS, nullptr, &h,
                               nullptr);
    }
    void set_dacl(const wchar_t* sddl) {
        PSECURITY_DESCRIPTOR sd = nullptr;
        REQUIRE(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, nullptr));
        const LONG rc = RegSetKeySecurity(h, DACL_SECURITY_INFORMATION, sd);
        LocalFree(sd);
        REQUIRE(rc == ERROR_SUCCESS);
    }
    ~ScratchKey() {
        if (h != nullptr) {
            if (denied) {
                PSECURITY_DESCRIPTOR sd = nullptr;
                if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:PAI(A;;KA;;;WD)", SDDL_REVISION_1, &sd,
                                                                         nullptr)) {
                    RegSetKeySecurity(h, DACL_SECURITY_INFORMATION, sd);
                    LocalFree(sd);
                }
            }
            RegCloseKey(h);
        }
        RegDeleteTreeW(HKEY_LOCAL_MACHINE, path.c_str());
    }
};

} // namespace

TEST_CASE("registry live: bam\\State is never read -- a scratch value under bam is a row, one under bam\\State "
          "is neither a row nor a gap (#6898)",
          "[echo][registry][windows][bam]") {
    if (!is_elevated())
        SKIP("cannot write HKLM\\SYSTEM (not elevated)");

    const std::string bam = "SYSTEM\\CurrentControlSet\\Services\\bam";
    const std::string leaf = yuzu::test::registry_scratch_prefix() + "bam-" + salt();
    ScratchKey control(bam + "\\" + leaf);                          // positive control: inside the watched root
    ScratchKey excluded(bam + "\\State\\UserSettings\\" + leaf);    // below the excluded subtree
    if (control.create() != ERROR_SUCCESS || excluded.create() != ERROR_SUCCESS)
        FAIL("the token is elevated but a scratch key under the bam service key could not be created");
    // Deny read to everyone: if the reader ever opens this key it is reported in `skipped`, which
    // is what makes the exclusion observable (the diff engine drops excluded keys on its own, so
    // a row-only assertion could not tell the reader's skip from the diff's).
    excluded.set_dacl(L"D:PAI(D;;KR;;;WD)(A;;KA;;;SY)(A;;KA;;;BA)");
    excluded.denied = true;

    auto reader = make_windows_registry_reader();
    const std::string root = "HKLM\\" + bam;
    const auto read = [&] { return reader.read_subtree(root, reader.now_ts() + kSnapshotBudget100ns); };

    const auto before = read();
    REQUIRE(before.status == RegistryReadStatus::Complete);

    DWORD v = 1;
    REQUIRE(RegSetValueExW(control.h, L"Probe", 0, REG_DWORD, reinterpret_cast<BYTE*>(&v), 4) == ERROR_SUCCESS);
    REQUIRE(RegSetValueExW(excluded.h, L"Probe", 0, REG_DWORD, reinterpret_cast<BYTE*>(&v), 4) == ERROR_SUCCESS);
    const auto after = read();
    REQUIRE(after.status == RegistryReadStatus::Complete);

    const auto mentions_leaf = [&](const std::string& s) { return s.find(leaf) != std::string::npos; };
    const auto d = diff_registry_snapshot(baseline_from_read(before), after, root, "notify", {0, 1}, 1);
    std::size_t control_rows = 0, excluded_rows = 0;
    for (const auto& c : d.candidates) {
        if (!mentions_leaf(c.key))
            continue;
        (c.key.find("\\State\\") != std::string::npos ? excluded_rows : control_rows)++;
    }
    CHECK(control_rows == 1);  // the write inside the root is seen
    CHECK(excluded_rows == 0); // the write below bam\State is not
    // No gap: the denied key was never opened, so it is not reported as skipped, and not read.
    CHECK(std::none_of(after.skipped.begin(), after.skipped.end(), mentions_leaf));
    CHECK(std::none_of(after.keys.begin(), after.keys.end(),
                       [&](const auto& kv) { return mentions_leaf(kv.first) && kv.first.find("\\State\\") != std::string::npos; }));
}

#endif // _WIN32
