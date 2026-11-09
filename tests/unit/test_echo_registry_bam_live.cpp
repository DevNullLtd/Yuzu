/**
 * test_echo_registry_bam_live.cpp -- the registry source's bam\State exclusion against the REAL
 * registry (#6898). Windows only; the translation unit is empty elsewhere.
 *
 * The exclusion is anchored to HKLM\SYSTEM\CurrentControlSet\Services\bam\State (see
 * registry_path_excluded), so a salted HKLM\SOFTWARE root cannot exercise it; this case watches
 * the real bam key and writes only scratch keys named with registry_scratch_prefix(), which
 * scripts/ci/check-registry-test-leftovers.ps1 scans under both bam roots.
 *
 * is_elevated() mirrors the helper in test_echo_registry_source.cpp (anonymous namespace there),
 * but holds the token in the HandlePtr owner where the original uses a manual CloseHandle. The
 * shared header is deferred because that file is edited by other work in flight.
 */

#ifdef _WIN32

#include "echo_registry_parsers.hpp"
#include "echo_registry_source.hpp"
#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdlib>
#include <memory>
#include <string>
#include <string_view>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <sddl.h>
#include <win_reg_handle.hpp>
#include <win_str.hpp>

using namespace yuzu::echo;

namespace {

// Scoped owners for the process token and the LocalAlloc'd security descriptor.
using HandlePtr = std::unique_ptr<void, decltype(&::CloseHandle)>;
using LocalPtr = std::unique_ptr<void, decltype(&::LocalFree)>;

bool is_elevated() {
    HANDLE raw = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw))
        return false;
    const HandlePtr token{raw, &::CloseHandle};
    TOKEN_ELEVATION e{};
    DWORD len = 0;
    const bool ok = GetTokenInformation(token.get(), TokenElevation, &e, sizeof(e), &len) != 0;
    return ok && e.TokenIsElevated != 0;
}

// Same rule as skip_or_fail in test_registry_write_local_dispatcher.cpp (which WARNs where this SKIPs): CI's non-pg step sets
// YUZU_REQUIRE_WINDOWS_REGISTRY_TESTS (non-empty, not "0") and runs elevated, so an environment
// SKIP there would be a silent green; it FAILs instead. Both macros throw, so callers need no return.
void skip_or_fail(const std::string& why) {
    const char* req = std::getenv("YUZU_REQUIRE_WINDOWS_REGISTRY_TESTS");
    if (req != nullptr && req[0] != '\0' && std::string_view{req} != "0")
        FAIL(why + " (YUZU_REQUIRE_WINDOWS_REGISTRY_TESTS is set)");
    SKIP(why);
}

// A scratch key below HKLM, deleted (with its contents) on destruction. A DACL set on the key
// through the held handle keeps working for writes; the destructor restores access through the
// same handle first so the delete cannot be refused.
struct ScratchKey {
    std::wstring path;
    HKEY h{nullptr};
    explicit ScratchKey(const std::string& below_hklm) : path(yuzu::win::to_wide(below_hklm)) {}
    ScratchKey(const ScratchKey&) = delete;
    ScratchKey& operator=(const ScratchKey&) = delete;
    LONG create() {
        return RegCreateKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, nullptr, 0, KEY_ALL_ACCESS, nullptr, &h,
                               nullptr);
    }
    LONG set_dacl(const wchar_t* sddl) {
        PSECURITY_DESCRIPTOR raw = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &raw, nullptr))
            return ERROR_INVALID_PARAMETER;
        const LocalPtr sd{raw, &::LocalFree};
        return RegSetKeySecurity(h, DACL_SECURITY_INFORMATION, sd.get());
    }
    ~ScratchKey() {
        if (h != nullptr) {
            set_dacl(L"D:PAI(A;;KA;;;SY)(A;;KA;;;BA)"); // best effort: restore access (SYSTEM, Administrators) so the delete cannot be refused
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
        skip_or_fail("cannot write HKLM\\SYSTEM (not elevated)");

    const std::string bam = "SYSTEM\\CurrentControlSet\\Services\\bam";
    // ScratchKey::create would otherwise create (and orphan) bam\State\UserSettings on a Windows without it.
    // The handles close at the end of the block, before the scratch keys are created. Opening
    // bam\State as well proves the token can read the level above UserSettings (an intermediate
    // key's access is not checked when a deeper path is opened), so a reader refused at State
    // is not mistaken for one that never descended.
    {
        yuzu::win::RegKey present;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\bam\\State", 0, KEY_READ,
                          present.put()) != ERROR_SUCCESS)
            skip_or_fail("bam\\State is not readable on this Windows");
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings", 0,
                          KEY_READ, present.put()) != ERROR_SUCCESS)
            skip_or_fail("bam\\State\\UserSettings is not present on this Windows");
    }
    const std::string leaf = yuzu::test::registry_scratch_prefix() + "bam-" +
                             std::to_string(yuzu::test::process_random_salt());
    ScratchKey control(bam + "\\" + leaf);                          // positive control: inside the watched root
    ScratchKey excluded(bam + "\\State\\UserSettings\\" + leaf);    // below the excluded subtree
    // Both are created before either can throw, so a failure here still unwinds both owners. An
    // elevated non-SYSTEM token may be refused; CI (LOCAL SYSTEM, the require flag set) FAILs.
    for (ScratchKey* k : {&control, &excluded}) {
        if (const LONG rc = k->create(); rc != ERROR_SUCCESS)
            skip_or_fail("cannot create a scratch key under the bam service key (error " + std::to_string(rc) + ")");
    }
    // Deny read to everyone: if the reader ever opens this key it is reported in `skipped`, which
    // is what makes the exclusion observable (the diff engine drops excluded keys on its own, so
    // a row-only assertion could not tell the reader's skip from the diff's).
    REQUIRE(excluded.set_dacl(L"D:PAI(D;;KR;;;WD)(A;;KA;;;SY)(A;;KA;;;BA)") == ERROR_SUCCESS);

    auto reader = make_windows_registry_reader();
    const std::string root = "HKLM\\" + bam;
    // A peer job planting a direct child of the shared bam root mid-walk changes the root's metadata
    // between the reader's two queries and caps the walk (Capped, partial keys). Re-read only that
    // status; Unreadable and the deadline stay fatal.
    const auto read = [&] {
        auto r = reader.read_subtree(root, reader.now_ts() + kSnapshotBudget100ns);
        for (int attempt = 1; attempt < 5 && r.status == RegistryReadStatus::Capped; ++attempt)
            r = reader.read_subtree(root, reader.now_ts() + kSnapshotBudget100ns);
        return r;
    };

    const auto before = read();
    INFO("status=" << static_cast<int>(before.status) << " skipped=" << before.skipped.size());
    REQUIRE(before.status == RegistryReadStatus::Complete);

    DWORD v = 1;
    REQUIRE(RegSetValueExW(control.h, L"Probe", 0, REG_DWORD, reinterpret_cast<BYTE*>(&v), 4) == ERROR_SUCCESS);
    REQUIRE(RegSetValueExW(excluded.h, L"Probe", 0, REG_DWORD, reinterpret_cast<BYTE*>(&v), 4) == ERROR_SUCCESS);
    const auto after = read();
    INFO("status=" << static_cast<int>(after.status) << " skipped=" << after.skipped.size());
    REQUIRE(after.status == RegistryReadStatus::Complete);

    const auto mentions_leaf = [&](const std::string& s) { return s.find(leaf) != std::string::npos; };
    const auto under_state = [](const std::string& s) { return s.find("\\State\\") != std::string::npos; };
    const auto d = diff_registry_snapshot(baseline_from_read(before), after, root, "notify", {0, 1}, 1);
    std::size_t control_rows = 0, excluded_rows = 0;
    for (const auto& c : d.candidates) {
        if (!mentions_leaf(c.key))
            continue;
        (under_state(c.key) ? excluded_rows : control_rows)++;
    }
    CHECK(control_rows == 1);  // the write inside the root is seen
    CHECK(excluded_rows == 0); // the write below bam\State is not
    // No gap: the denied key was never opened, so it is not reported as skipped, and not read.
    CHECK(std::none_of(after.skipped.begin(), after.skipped.end(), mentions_leaf));
    CHECK(std::none_of(after.keys.begin(), after.keys.end(),
                       [&](const auto& kv) { return mentions_leaf(kv.first) && under_state(kv.first); }));
}

#endif // _WIN32
