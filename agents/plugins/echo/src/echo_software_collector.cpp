/**
 * echo_software_collector.cpp -- Installed-software enumeration for the Echo
 * `software` source (Phase 8 Wave 1).
 *
 * Windows enumerates the MACHINE-WIDE registry Uninstall keys only:
 * HKLM ...\Uninstall (64-bit + WOW6432Node 32-bit) — cheap, no hive mounts, no
 * per-user identity. The source is machine scope only: an install/uninstall
 * event is attributed to the host, never to a Windows profile, so the capture
 * carries no personal data (#1620). (An earlier design also enumerated per-user
 * HKU\<SID> hives, mounting NTUSER.DAT for logged-off profiles; that scope — and
 * its profile-name PII — was dropped along with the hive-mount machinery.)
 *
 * Registry handles are owned by a RAII guard (RegKey) so an exception (e.g.
 * std::bad_alloc while building a result string) cannot leak an HKEY.
 *
 * Registry STRING reads use the wide Reg*W APIs and convert to UTF-8 via the
 * shared win_str.hpp helpers (yuzu::win::reg_sz_to_utf8), per the project-wide
 * wide-only registry-read contract (#1662/#1682). The old ANSI Reg*A path
 * returned system-codepage bytes that silently corrupted non-ASCII application
 * names and publishers before storage. Linux/macOS: the entry point returns
 * empty (kPlanned) — a fast-follow will reuse the installed_apps dpkg/rpm/pkgutil
 * enumeration here.
 */

#include "echo_collectors.hpp"
#include "echo_version.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <atomic>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <win_str.hpp> // shared yuzu::win wide<->UTF-8 helpers (#1681/#1682)
#endif

namespace yuzu::echo {

#ifdef _WIN32

namespace {

constexpr const char* kMachineUninstall = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

// RAII owner for an HKEY. Closes on destruction so an exception between open and
// the (former) manual RegCloseKey cannot leak the handle. Non-copyable and
// non-movable (the user-declared dtor suppresses the implicit move; a defaulted
// move would copy the raw HKEY and double-close — we never need to move one).
class RegKey {
public:
    RegKey() = default;
    RegKey(const RegKey&) = delete;
    RegKey& operator=(const RegKey&) = delete;
    ~RegKey() {
        if (h_)
            RegCloseKey(h_);
    }
    HKEY* put() { return &h_; } // for the &phkResult out-param of RegOpenKeyExW
    HKEY get() const { return h_; }

private:
    HKEY h_{nullptr};
};

// Warn once (per process) when the per-cycle software entry cap is hit. Unlike
// the ARP/DNS auto-clearing rate-limit, a host that genuinely owns >8192
// installed entries would truncate on EVERY tick, so the flag latches and never
// resets — one warning, not a per-tick spam. The append loop bounds memory + tick
// duration regardless of whether the warn fires (#1620).
void note_software_truncation() {
    static std::atomic<bool> warned{false};
    if (!warned.exchange(true)) {
        spdlog::warn("Echo software: per-cycle entry cap {} reached — truncating installed-software "
                     "inventory (further truncation warnings suppressed)",
                     kSoftwareEntryCap);
    }
}

// One-entry-per-name: sort then keep the highest-versioned of any same-name
// duplicates (e.g. the 64-bit and 32-bit views of a product sharing a
// DisplayName), so the diff key (name) is unambiguous. Versions compare
// numerically (compare_versions), not lexicographically — "10.0" outranks "9.0"
// so the diff keeps the real-latest build (#1620).
void dedup(std::vector<SoftwareInfo>& apps) {
    std::sort(apps.begin(), apps.end(), [](const SoftwareInfo& a, const SoftwareInfo& b) {
        if (a.name != b.name) return a.name < b.name;
        return compare_versions(a.version, b.version) > 0; // descending → unique keeps the highest
    });
    apps.erase(std::unique(apps.begin(), apps.end(),
                           [](const SoftwareInfo& a, const SoftwareInfo& b) {
                               return a.name == b.name;
                           }),
               apps.end());
}

// Enumerate one Uninstall key, appending SoftwareInfo records. SystemComponent=1
// and nameless entries are skipped. `subkey` is an ASCII key PATH (compile-time
// literal); it is converted to wide for the open so the whole read path is Reg*W.
void enumerate_uninstall_key(HKEY root, const char* subkey, REGSAM extra_sam,
                             std::vector<SoftwareInfo>& apps) {
    // Per-cycle cap (#1620): `apps` is the shared accumulator across the 64-bit
    // and 32-bit machine views in one tick, so a prior key may already have filled
    // it.
    if (apps.size() >= kSoftwareEntryCap) {
        note_software_truncation();
        return;
    }

    RegKey hkey;
    if (RegOpenKeyExW(root, yuzu::win::to_wide(subkey).c_str(), 0,
                      KEY_READ | KEY_ENUMERATE_SUB_KEYS | extra_sam, hkey.put()) != ERROR_SUCCESS) {
        return;
    }

    // App subkey names can be non-ASCII (some installers key on the DisplayName),
    // so enumerate wide and re-open with the wide name directly — an ANSI round
    // trip could mangle the name and fail the re-open.
    wchar_t name_buf[256]{};
    DWORD idx = 0;
    DWORD name_len = ARRAYSIZE(name_buf); // RegEnumKeyExW length is in CHARACTERS, not bytes

    while (RegEnumKeyExW(hkey.get(), idx++, name_buf, &name_len, nullptr, nullptr, nullptr,
                         nullptr) == ERROR_SUCCESS) {
        if (apps.size() >= kSoftwareEntryCap) {
            note_software_truncation();
            break;
        }
        RegKey app_key;
        if (RegOpenKeyExW(hkey.get(), name_buf, 0, KEY_READ | extra_sam, app_key.put()) ==
            ERROR_SUCCESS) {
            auto read_str = [&](const wchar_t* value_name) -> std::string {
                wchar_t buf[512]{};
                DWORD size = sizeof(buf); // bytes — RegQueryValueExW reports/consumes byte counts
                DWORD type = 0;
                if (RegQueryValueExW(app_key.get(), value_name, nullptr, &type,
                                     reinterpret_cast<LPBYTE>(buf), &size) == ERROR_SUCCESS) {
                    // Accept REG_EXPAND_SZ as well as REG_SZ — some installers store
                    // these values with embedded environment refs. reg_sz_to_utf8
                    // stops at the first NUL (correct for REG_SZ/REG_EXPAND_SZ) and
                    // returns valid UTF-8, so no system-codepage corruption and no
                    // separate sanitisation pass is needed.
                    if ((type == REG_SZ || type == REG_EXPAND_SZ) && size > 0) {
                        DWORD cap = size < sizeof(buf) ? size : sizeof(buf);
                        return yuzu::win::reg_sz_to_utf8(buf, cap);
                    }
                }
                return {};
            };

            // SystemComponent is canonically a REG_DWORD (=1 hides the entry from
            // Add/Remove Programs); a REG_SZ-only read made the filter a permanent
            // no-op so system components/patches were collected despite the manual's
            // contract (#1620). Read the DWORD form, falling back to the rare string
            // form. (A DWORD read carries no encoding; it stays correct under W.)
            auto system_component_set = [&]() -> bool {
                DWORD val = 0;
                DWORD size = sizeof(val);
                DWORD type = 0;
                if (RegQueryValueExW(app_key.get(), L"SystemComponent", nullptr, &type,
                                     reinterpret_cast<LPBYTE>(&val), &size) == ERROR_SUCCESS &&
                    type == REG_DWORD && size == sizeof(DWORD)) {
                    return val == 1;
                }
                return read_str(L"SystemComponent") == "1";
            };

            auto display_name = read_str(L"DisplayName");
            if (!display_name.empty() && !system_component_set()) {
                SoftwareInfo app;
                app.name = std::move(display_name);
                app.version = read_str(L"DisplayVersion");
                app.publisher = read_str(L"Publisher");
                // InstallDate is usually REG_SZ "YYYYMMDD", but some installers
                // store it as a REG_DWORD number — fall back to that so the column
                // is not silently empty.
                auto install_date = read_str(L"InstallDate");
                if (install_date.empty()) {
                    DWORD val = 0;
                    DWORD dsize = sizeof(val);
                    DWORD dtype = 0;
                    if (RegQueryValueExW(app_key.get(), L"InstallDate", nullptr, &dtype,
                                         reinterpret_cast<LPBYTE>(&val), &dsize) == ERROR_SUCCESS &&
                        dtype == REG_DWORD && dsize == sizeof(DWORD) && val != 0) {
                        install_date = std::to_string(val);
                    }
                }
                app.install_date = std::move(install_date);
                apps.push_back(std::move(app));
            }
        }
        name_len = ARRAYSIZE(name_buf);
    }
}

} // namespace

void enumerate_machine_software(std::vector<SoftwareInfo>& out) {
    // 64-bit then 32-bit (WoW6432Node) HKLM Uninstall.
    enumerate_uninstall_key(HKEY_LOCAL_MACHINE, kMachineUninstall, KEY_WOW64_64KEY, out);
    enumerate_uninstall_key(HKEY_LOCAL_MACHINE, kMachineUninstall, KEY_WOW64_32KEY, out);
    dedup(out);
}

#else // !_WIN32

// Linux/macOS: kPlanned. The schema is queryable-empty; a fast-follow will reuse
// the installed_apps dpkg/rpm/pkgutil enumeration here.
void enumerate_machine_software(std::vector<SoftwareInfo>& /*out*/) {}

#endif

} // namespace yuzu::echo
