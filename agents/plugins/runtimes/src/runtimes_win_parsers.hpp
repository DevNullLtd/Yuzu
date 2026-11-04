/**
 * runtimes_win_parsers.hpp -- the Windows leg's PEP 514 registry walk for the runtimes plugin's
 * `python` action, templated on a registry-ops seam (installed_apps_registry_walk.hpp shape): the
 * plugin uses RealRegOps, the unit suite a scripted fake and, separately, a salted scratch key.
 *
 * WHAT IS READ (rung 1, zero subprocess): HKLM\SOFTWARE\Python\PythonCore\<tag>, in BOTH registry
 * views (64-bit first, then WOW6432Node): `Version`, `SysVersion` and the default value of the
 * `InstallPath` subkey. One row per tag; the same install path seen through both views is one row
 * (the 64-bit one), and rows are emitted sorted by (version, install path). HKCU and per-user
 * hives are NEVER opened (machine scope only). Only the `PythonCore` company (python.org) is
 * walked: other PEP 514 companies (Anaconda, ...) are not.
 *
 * FAILURE NEVER READS AS ABSENT. An absent PythonCore key is silent (`supported` + zero rows: no
 * python.org install). Any other failed open, an enumeration error, a tag name too long for the name
 * buffer and a denied tag/InstallPath open record `windows:runtimes:python_reg:<cause>`. A missing or
 * unparsable VALUE is a per-item metadata shortfall: the row reports what was found (down to the
 * tag's major.minor) and raises no token.
 *
 * BOUNDED. One kMaxTagsVisited counter across both views (every enumerated name counts, an over-long
 * one too; one record per tag, so it also caps the rows) and ONE RowByteBudget of kMaxTagsVisited
 * rows and kMaxRowBytes bytes; exhausting either records `windows:runtimes:python_reg:row_cap` and
 * stops. A value is read up to kMaxValueBytes, longer reads as absent.
 */
#pragma once

#ifdef _WIN32

#include "runtimes_legs.hpp"
#include "runtimes_python_parsers.hpp"

#include <row_byte_budget.hpp> // yuzu::shared::RowByteBudget (agents/shared)
#include <win_str.hpp>         // yuzu::win::from_wide / to_wide (agents/shared)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <string>
#include <string_view>
#include <vector>

namespace yuzu::runtimes::win {

inline constexpr std::string_view kTokAccessDenied = "windows:runtimes:python_reg:access_denied";
inline constexpr std::string_view kTokOpenFailed = "windows:runtimes:python_reg:open_failed";
inline constexpr std::string_view kTokEnumFailed = "windows:runtimes:python_reg:enum_failed";
inline constexpr std::string_view kTokNameTooLong = "windows:runtimes:python_reg:name_too_long";
inline constexpr std::string_view kTokRowCap = "windows:runtimes:python_reg:row_cap";

inline constexpr std::size_t kMaxRowBytes = 1024 * 1024;
inline constexpr std::size_t kMaxTagsVisited = 512;
inline constexpr DWORD kMaxValueBytes = 64 * 1024;

/// The registry calls the walk makes, as one seam. `read_str` returns "" for an absent, mistyped or
/// oversized value; `value_name == nullptr` reads the key's default value.
struct RealRegOps {
    LSTATUS open(HKEY parent, const wchar_t* sub, REGSAM sam, HKEY* out) const {
        return RegOpenKeyExW(parent, sub, 0, sam, out);
    }
    LSTATUS enum_key(HKEY key, DWORD idx, wchar_t* name, DWORD* name_len) const {
        return RegEnumKeyExW(key, idx, name, name_len, nullptr, nullptr, nullptr, nullptr);
    }
    void close(HKEY key) const { RegCloseKey(key); }
    std::string read_str(HKEY key, const wchar_t* value_name) const {
        DWORD type = 0;
        DWORD size = 0;
        if (RegQueryValueExW(key, value_name, nullptr, &type, nullptr, &size) != ERROR_SUCCESS)
            return {};
        if ((type != REG_SZ && type != REG_EXPAND_SZ) || size < sizeof(wchar_t) ||
            size > kMaxValueBytes)
            return {};
        std::wstring buf(size / sizeof(wchar_t) + 1, L'\0');
        DWORD got = size;
        if (RegQueryValueExW(key, value_name, nullptr, &type, reinterpret_cast<LPBYTE>(buf.data()),
                             &got) != ERROR_SUCCESS)
            return {}; // grew between the two reads (ERROR_MORE_DATA) or vanished: absent
        return yuzu::win::reg_sz_to_utf8(buf.c_str(), got);
    }
};

namespace detail {

[[nodiscard]] inline std::string_view open_token(LSTATUS rc) noexcept {
    return rc == ERROR_ACCESS_DENIED ? kTokAccessDenied : kTokOpenFailed;
}

[[nodiscard]] inline bool is_absent(LSTATUS rc) noexcept {
    return rc == ERROR_FILE_NOT_FOUND || rc == ERROR_PATH_NOT_FOUND;
}

} // namespace detail

/// The python rows of this host: both views of HKLM\SOFTWARE\Python\PythonCore, failures in `acc`.
/// `root` / `subkey` are parameters only so the unit suite can point the real registry calls at an
/// isolated scratch key; production uses the defaults and never opens HKCU or a user hive.
template <class Ops>
[[nodiscard]] std::vector<std::string> python_rows(
    const Ops& ops, yuzu::shared::ConstraintAccumulator& acc, HKEY root = HKEY_LOCAL_MACHINE,
    const wchar_t* subkey = L"SOFTWARE\\Python\\PythonCore") {
    // Closes through `ops`, so a fake's handles never reach RegCloseKey. Owns a raw HKEY, so it is
    // not copyable (a copy would close the handle twice); the constructor keeps `Guard g{ops, h}`.
    struct Guard {
        const Ops& ops;
        HKEY h = nullptr;
        Guard(const Ops& o, HKEY k) noexcept : ops(o), h(k) {}
        Guard(const Guard&) = delete;
        ~Guard() {
            if (h) ops.close(h);
        }
    };
    constexpr DWORD kNameLen = 256; // WCHAR count, the unit RegEnumKeyExW's lpcchName uses
    std::vector<PythonRecord> recs;
    std::size_t tags_seen = 0;
    bool capped = false;
    for (const REGSAM view : {KEY_WOW64_64KEY, KEY_WOW64_32KEY}) {
        if (capped) break;
        HKEY core = nullptr;
        const LSTATUS orc =
            ops.open(root, subkey, KEY_READ | KEY_ENUMERATE_SUB_KEYS | view, &core);
        if (orc != ERROR_SUCCESS) {
            if (!detail::is_absent(orc)) acc.add_failure(detail::open_token(orc));
            continue;
        }
        Guard core_guard{ops, core};
        wchar_t name[kNameLen]{};
        for (DWORD idx = 0;; ++idx) {
            DWORD name_len = kNameLen;
            const LSTATUS erc = ops.enum_key(core, idx, name, &name_len);
            if (erc == ERROR_NO_MORE_ITEMS) break;
            if (erc != ERROR_SUCCESS && erc != ERROR_MORE_DATA) {
                acc.add_failure(kTokEnumFailed);
                break;
            }
            // Every enumerated name counts, an over-long one too, so a key stuffed with them ends
            // at the cap instead of looping to its last subkey.
            if (++tags_seen > kMaxTagsVisited) {
                acc.add_failure(kTokRowCap);
                capped = true;
                break;
            }
            if (erc == ERROR_MORE_DATA) { // a >255-WCHAR tag name is not a Python version
                acc.add_failure(kTokNameTooLong);
                continue;
            }
            HKEY tag_key = nullptr;
            const LSTATUS trc = ops.open(core, name, KEY_READ | view, &tag_key);
            if (detail::is_absent(trc)) continue; // vanished between enumerate and open
            if (trc != ERROR_SUCCESS) {
                acc.add_failure(detail::open_token(trc));
                continue;
            }
            Guard tag_guard{ops, tag_key};
            const std::string tag = yuzu::win::from_wide(name, static_cast<int>(name_len));
            PythonRecord rec;
            rec.flavour = PythonFlavour::cpython;
            rec.vendor = "PythonCore";
            rec.version = python_version_from_pep514(ops.read_str(tag_key, L"Version"),
                                                     ops.read_str(tag_key, L"SysVersion"), tag)
                              .value_or(std::string{});
            HKEY ip_key = nullptr;
            const LSTATUS irc = ops.open(tag_key, L"InstallPath", KEY_READ | view, &ip_key);
            if (irc == ERROR_SUCCESS) {
                Guard ip_guard{ops, ip_key};
                rec.install_path = ops.read_str(ip_key, nullptr);
            } else if (!detail::is_absent(irc)) {
                acc.add_failure(detail::open_token(irc));
            }
            recs.push_back(std::move(rec));
        }
    }
    dedupe_python_rows(recs);
    sort_python_rows(recs); // registry enumeration order is unspecified: emit a stable order
    yuzu::shared::RowByteBudget budget{kMaxTagsVisited, kMaxRowBytes};
    std::vector<std::string> rows;
    for (const auto& r : recs) {
        auto row = python_row(r);
        if (!budget.charge(row.size())) {
            acc.add_failure(kTokRowCap);
            break;
        }
        rows.push_back(std::move(row));
    }
    return rows;
}

/// The Windows leg body over an ops seam: `python` is read, the dotnet/jvm actions stay planned.
template <class Ops>
int run_windows_with(yuzu::CommandContext& ctx, Action a, const Ops& ops) {
    if (a != Action::python) {
        emit_planned(ctx, a, "windows:planned");
        return 0;
    }
    yuzu::shared::ConstraintAccumulator acc;
    const auto rows = python_rows(ops, acc);
    emit_read(ctx, a, rows, acc);
    return 0;
}

} // namespace yuzu::runtimes::win

#endif // _WIN32
