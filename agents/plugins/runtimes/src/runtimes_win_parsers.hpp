/**
 * runtimes_win_parsers.hpp -- the Windows leg's registry walks for the runtimes plugin (`python`,
 * `dotnet`, `jvm`), templated on a registry-ops seam (installed_apps_registry_walk.hpp shape): the
 * plugin uses RealRegOps, the unit suite a scripted fake and, separately, a salted scratch key.
 *
 * TWO LAYERS IN ONE HEADER. The first (above the _WIN32 guard) is pure: the .NET Framework release
 * table, the JVM home bookkeeping and the row finisher have no OS call and are unit-tested on every
 * OS. The second (_WIN32 only) is the registry/file shell and the three walks.
 *
 * WHAT IS READ (rung 1, zero subprocess, no directory walk). Every walk reads BOTH registry views of
 * HKLM (64-bit first, then WOW6432Node). HKCU and per-user hives are NEVER opened (machine scope).
 *   python  HKLM\SOFTWARE\Python\PythonCore\<tag>: `Version`, `SysVersion` and the default value of
 *           the `InstallPath` subkey. One row per tag; the same install path seen through both views
 *           is one row (the 64-bit one), sorted by (version, install path). Only the `PythonCore`
 *           company (python.org) is walked: other PEP 514 companies (Anaconda, ...) are not.
 *   dotnet  HKLM\SOFTWARE\dotnet\Setup\InstalledVersions\<arch>\sharedfx\<framework> (flavour
 *           `runtime`) and \<arch>\sdk (flavour `sdk`): one row per value, the value NAME is the
 *           version and a string value's data the install path; the .NET installers write a DWORD 1
 *           there instead, so the path then falls back to the arch key's `InstallLocation`. Plus the
 *           .NET Framework (flavour `netfx`): NDP\v4\Full `Release` mapped through a fixed table,
 *           NDP\v3.5 `Version`. The .NET shared frameworks sit in the WOW6432Node view on a real
 *           host, so reading one view only would miss them. Vendor is `Microsoft`.
 *   jvm     the home directories registered by JavaSoft (JDK, Java Development Kit, Java Runtime
 *           Environment, JRE), Eclipse Adoptium (JDK, JRE), Microsoft (JDK) and Azul Zulu, deduplicated by home path,
 *           then ONE bounded read (64 KiB) of `<home>\release` through the shared release parser.
 *           Vendor and flavour come from that file, NEVER from the registry vendor key: a non-Oracle
 *           JDK (Microsoft's) also writes the Oracle JavaSoft key.
 *
 * FAILURE NEVER READS AS ABSENT. An absent root is silent (`supported` + zero rows). Any other failed
 * open, an enumeration error, a name too long for the buffer and a denied open record
 * `windows:runtimes:<python|dotnet|jvm>_reg:<cause>`. A missing or unparsable VALUE is a per-item
 * metadata shortfall: the row reports what was found and raises no token (a JVM home value is the exception, below). A JVM home whose `release`
 * file exists but cannot be read (denied, a reparse point, over the cap, a non-local path) is still
 * a row (version = the registry's version tag, flavour `unmodelled`) and records
 * `windows:runtimes:jvm:release_unreadable`; a home with no `release` file at all is the same row
 * without a token. The release file is opened by ONE kernel name resolution relative to an open
 * handle on the drive root (yuzu::win::open_file_no_reparse, agents/shared/win_no_reparse_open.hpp:
 * NtCreateFile with OBJ_DONT_REPARSE), so no component below the drive root is a reparse point that
 * gets followed: a junction or symlink in any ancestor, or on the leaf, is refused as unreadable
 * before it is followed (a link to a UNC path never makes the service connect outbound), and there
 * is no check-then-open window. A name with a `.`, `..` or empty segment or a component ending in
 * '.' or ' ' (spellings the Win32 layer would rewrite and the NT open does not) is refused as
 * unreadable rather than resolved. A Windows build that rejects OBJ_DONT_REPARSE (the open answers
 * STATUS_INVALID_PARAMETER) reads every release file as unreadable, never through a path-based
 * fallback, and logs that cause once per process. The open is exercised by the Windows-only cases
 * `runtimes win: read_file_bounded follows no reparse point below the drive root` and
 * `runtimes win: drive_relative_name*` (tests/unit/test_runtimes_win_walk.cpp) on the Windows test
 * leg: they passed, with the flag accepted, on Windows build 10.0.26200.9974 (native MSVC run, 2026-11-11),
 * and no Windows floor is claimed. A JVM key whose home value is present but empty, mistyped
 * or oversized records
 * `windows:runtimes:jvm:home_unusable` (an absent value stays silent). The read has no deadline,
 * a disclosed residual on a dead FIXED volume.
 *
 * BOUNDED. One kMaxEntriesVisited counter per walk across both views (every enumerated name and
 * value counts, an over-long one too) and ONE RowByteBudget of kMaxEntriesVisited rows and
 * kMaxRowBytes bytes; exhausting either records the walk's `row_cap` token and stops. A value is read up to
 * kMaxValueBytes, longer reads as absent.
 */
#pragma once

#include "runtimes_parsers.hpp"

#include <row_byte_budget.hpp> // yuzu::shared::RowByteBudget (agents/shared)
#include <win_no_reparse_open.hpp> // yuzu::win::drive_relative_name (every OS) + open_file_no_reparse (Windows)

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// -- pure layer (every OS) ------------------------------------------------------------------

namespace yuzu::runtimes::win {

inline constexpr std::size_t kMaxRowBytes = 1024 * 1024;
inline constexpr std::size_t kMaxEntriesVisited = 512;
/// The JVM `release` file read cap (a real one is ~1.3 KB; the shared parser's own contract is 64 KiB).
inline constexpr std::size_t kMaxReleaseBytes = 64 * 1024;

/// The constraint tokens of one registry walk. The python tokens stay below (kTok*); dotnet and jvm
/// mirror them under their own prefix.
struct RegTokens {
    std::string_view access_denied;
    std::string_view open_failed;
    std::string_view enum_failed;
    std::string_view name_too_long;
    std::string_view row_cap;
};

inline constexpr RegTokens kDotnetTokens{
    "windows:runtimes:dotnet_reg:access_denied", "windows:runtimes:dotnet_reg:open_failed",
    "windows:runtimes:dotnet_reg:enum_failed", "windows:runtimes:dotnet_reg:name_too_long",
    "windows:runtimes:dotnet_reg:row_cap"};
inline constexpr RegTokens kJvmTokens{
    "windows:runtimes:jvm_reg:access_denied", "windows:runtimes:jvm_reg:open_failed",
    "windows:runtimes:jvm_reg:enum_failed", "windows:runtimes:jvm_reg:name_too_long",
    "windows:runtimes:jvm_reg:row_cap"};
/// A home's `release` file exists but could not be read (denied, a reparse point, over the cap, a
/// non-local path). Absent file: no token.
inline constexpr std::string_view kTokJvmReleaseUnreadable = "windows:runtimes:jvm:release_unreadable";
/// A registered JVM key whose home value (JavaHome / Path / InstallationPath) exists but is empty,
/// mistyped or oversized: a registered install with no usable home, never a silent drop. An ABSENT
/// value stays silent (the key is not a home registration).
inline constexpr std::string_view kTokJvmHomeUnusable = "windows:runtimes:jvm:home_unusable";

// -- .NET -----------------------------------------------------------------------------------------

inline constexpr std::string_view kFlavourRuntime = "runtime";
inline constexpr std::string_view kFlavourSdk = "sdk";
inline constexpr std::string_view kFlavourNetfx = "netfx";

struct NetfxRelease {
    std::uint32_t release;
    std::string_view version;
};

/// Microsoft's documented `Release` DWORD thresholds of NDP\v4\Full, ascending: the HIGHEST
/// threshold <= the value wins (an install of a later servicing build reports a larger number).
inline constexpr std::array<NetfxRelease, 11> kNetfxReleases{{{378389, "4.5"},
                                                              {378675, "4.5.1"},
                                                              {379893, "4.5.2"},
                                                              {393295, "4.6"},
                                                              {394254, "4.6.1"},
                                                              {394802, "4.6.2"},
                                                              {460798, "4.7"},
                                                              {461308, "4.7.1"},
                                                              {461808, "4.7.2"},
                                                              {528040, "4.8"},
                                                              {533320, "4.8.1"}}};

/// "" when `release` is below the first threshold (not a version this table knows): the row then
/// reports version `-`.
[[nodiscard]] constexpr std::string_view netfx_version_from_release(std::uint32_t release) noexcept {
    std::string_view v;
    for (const auto& e : kNetfxReleases)
        if (release >= e.release) v = e.version;
    return v;
}

/// A dotnet InstalledVersions value NAME is the version; anything else reads `-`, never guessed.
[[nodiscard]] inline std::string_view dotnet_version_from_value_name(std::string_view name) noexcept {
    return yuzu::runtimes::detail::looks_like_version_dir(name) ? name : std::string_view{};
}

/// dotnet|<runtime|sdk|netfx>|<version>|<install_path>|Microsoft
[[nodiscard]] inline std::string dotnet_registry_row(std::string_view flavour,
                                                     std::string_view version,
                                                     std::string_view install_path) {
    return format_runtime_row("dotnet", flavour, version, install_path, "Microsoft");
}

// -- JVM ------------------------------------------------------------------------------------------

/// One registered JVM home. `key` is the dedupe identity (case-folded, separator-folded, no trailing
/// separator), `tag` the registry's version subkey name, which stands in for an unreadable release.
struct JvmHome {
    std::string key;
    std::string home;
    std::string tag;
};

[[nodiscard]] inline std::string jvm_home_key(std::string_view home) {
    std::string k;
    k.reserve(home.size());
    for (const char c : home)
        k += c == '/' ? '\\' : (c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c);
    while (!k.empty() && k.back() == '\\') k.pop_back();
    return k;
}

/// `X:\...` or `X:/...` only: a UNC, device (`\\.\`, `\\?\`) or relative path is never opened.
[[nodiscard]] inline bool is_local_drive_path(std::string_view p) noexcept {
    return p.size() >= 3 && ((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) &&
           p[1] == ':' && (p[2] == '\\' || p[2] == '/');
}

[[nodiscard]] inline std::string jvm_release_path(std::string_view home) {
    std::string p{home};
    while (!p.empty() && (p.back() == '\\' || p.back() == '/')) p.pop_back();
    return p + "\\release";
}

/// Records a home once however many views / vendor keys name it. Duplicates keep the greatest tag,
/// so which of `21` and `21.0.12.101` stands in for an unreadable release never depends on
/// enumeration order. An empty home is not an install.
inline void add_jvm_home(std::vector<JvmHome>& homes, std::string home, std::string tag) {
    if (home.empty()) return;
    auto key = jvm_home_key(home);
    for (auto& h : homes) {
        if (h.key == key) {
            if (tag > h.tag) h.tag = std::move(tag);
            return;
        }
    }
    homes.push_back({std::move(key), std::move(home), std::move(tag)});
}

/// The row of one home. `release` is the bounded read: nullopt = the file exists but was not
/// readable; engaged-and-empty = no file. Either way (and for a file with no version key) the home is
/// still a row, flavour `unmodelled`, version = the registry's tag.
[[nodiscard]] inline std::string jvm_home_row(const JvmHome& h,
                                              const std::optional<std::string>& release) {
    if (release) {
        if (auto row = jvm_row(parse_release_file(*release), h.home)) return *std::move(row);
    }
    return format_runtime_row("jvm", flavour_token(JvmFlavour::unmodelled), h.tag, h.home, "");
}

// -- rows -----------------------------------------------------------------------------------------

/// Sorted (registry enumeration order is unspecified), exact duplicates removed, then admitted under
/// one RowByteBudget; the first refusal records `row_cap_token` and ends the list.
[[nodiscard]] inline std::vector<std::string> finish_rows(std::vector<std::string> rows,
                                                          yuzu::shared::ConstraintAccumulator& acc,
                                                          std::string_view row_cap_token) {
    std::sort(rows.begin(), rows.end());
    rows.erase(std::unique(rows.begin(), rows.end()), rows.end());
    yuzu::shared::RowByteBudget budget{kMaxEntriesVisited, kMaxRowBytes};
    std::size_t kept = 0;
    while (kept < rows.size() && budget.charge(rows[kept].size())) ++kept;
    if (kept < rows.size()) {
        acc.add_failure(row_cap_token);
        rows.erase(rows.begin() + static_cast<std::ptrdiff_t>(kept), rows.end());
    }
    return rows;
}

} // namespace yuzu::runtimes::win

// -- Windows shell --------------------------------------------------------------------------------

#ifdef _WIN32

#include "runtimes_legs.hpp"
#include "runtimes_python_parsers.hpp"

#include <win_str.hpp> // yuzu::win::from_wide / to_wide (agents/shared)

#include <spdlog/spdlog.h>

#include <atomic>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace yuzu::runtimes::win {

inline constexpr std::string_view kTokAccessDenied = "windows:runtimes:python_reg:access_denied";
inline constexpr std::string_view kTokOpenFailed = "windows:runtimes:python_reg:open_failed";
inline constexpr std::string_view kTokEnumFailed = "windows:runtimes:python_reg:enum_failed";
inline constexpr std::string_view kTokNameTooLong = "windows:runtimes:python_reg:name_too_long";
inline constexpr std::string_view kTokRowCap = "windows:runtimes:python_reg:row_cap";

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
    /// True when the value exists whatever its type or size (read_str folds absent, mistyped and
    /// oversized into ""; this tells a registered-but-unusable value from an absent one).
    bool has_value(HKEY key, const wchar_t* value_name) const {
        DWORD size = 0;
        const LSTATUS rc = RegQueryValueExW(key, value_name, nullptr, nullptr, nullptr, &size);
        return rc != ERROR_FILE_NOT_FOUND && rc != ERROR_PATH_NOT_FOUND;
    }
    /// nullopt for an absent or non-DWORD value.
    std::optional<DWORD> read_dword(HKEY key, const wchar_t* value_name) const {
        DWORD type = 0;
        DWORD v = 0;
        DWORD size = sizeof(v);
        if (RegQueryValueExW(key, value_name, nullptr, &type, reinterpret_cast<LPBYTE>(&v),
                             &size) != ERROR_SUCCESS ||
            type != REG_DWORD || size != sizeof(v))
            return std::nullopt;
        return v;
    }
    /// One value of `key`: `name` / `name_len` (WCHARs, in: capacity incl. the NUL, out: length) as
    /// RegEnumKeyExW. `data` is the value's UTF-8 text for REG_SZ / REG_EXPAND_SZ up to kMaxValueBytes
    /// and empty for any other type or size (a DWORD value is still enumerated, with no text). Returns
    /// the enumeration status: ERROR_MORE_DATA is a name over the buffer, ERROR_NO_MORE_ITEMS the end.
    LSTATUS enum_value(HKEY key, DWORD idx, wchar_t* name, DWORD* name_len,
                       std::string* data) const {
        data->clear();
        const DWORD capacity = *name_len;
        DWORD type = 0;
        DWORD size = 0;
        const LSTATUS rc = RegEnumValueW(key, idx, name, name_len, nullptr, &type, nullptr, &size);
        if (rc != ERROR_SUCCESS) return rc;
        if ((type != REG_SZ && type != REG_EXPAND_SZ) || size < sizeof(wchar_t) ||
            size > kMaxValueBytes)
            return ERROR_SUCCESS;
        std::wstring buf(size / sizeof(wchar_t) + 1, L'\0');
        DWORD got = size;
        DWORD again = capacity;
        const LSTATUS rc2 = RegEnumValueW(key, idx, name, &again, nullptr, &type,
                                          reinterpret_cast<LPBYTE>(buf.data()), &got);
        if (rc2 != ERROR_SUCCESS) return rc2; // grew or vanished between the two reads
        *name_len = again;
        *data = yuzu::win::reg_sz_to_utf8(buf.c_str(), got);
        return ERROR_SUCCESS;
    }
    /// One bounded read of a local-drive file, opened by ONE kernel name resolution relative to the
    /// drive-root handle with no reparse point followed below the root (yuzu::win::
    /// open_file_no_reparse: NtCreateFile + OBJ_DONT_REPARSE, so a junction or symlink swapped into
    /// an ancestor is never followed and there is no check-then-open window). It has no deadline:
    /// the open and ReadFile on a dead FIXED volume (iSCSI, USB, VHD) can block the sync thread, a
    /// disclosed residual shared with the other Windows readers.
    /// engaged-and-empty: the file does not exist. nullopt: it exists (or may) but is not read --
    /// not a plain `X:\...` path (a `.`/`..`/empty segment or a component ending in '.' or ' ' is
    /// refused too), not on a fixed local drive (remote, removable, optical, RAM or unknown), a
    /// reparse point anywhere below the root, a directory, not a disk file, over `cap` bytes, an
    /// open / read failure, or a Windows build that rejects OBJ_DONT_REPARSE (logged once).
    std::optional<std::string> read_file_bounded(const std::wstring& path, std::size_t cap) const {
        if (path.size() < 3 || path[1] != L':' || (path[2] != L'\\' && path[2] != L'/'))
            return std::nullopt;
        const wchar_t root[] = {path[0], L':', L'\\', L'\0'};
        if (GetDriveTypeW(root) != DRIVE_FIXED) return std::nullopt;
        auto opened = yuzu::win::open_file_no_reparse(path);
        if (opened.status == yuzu::win::NoReparseOpen::absent) return std::string{};
        if (opened.status == yuzu::win::NoReparseOpen::unsupported) {
            static std::atomic_flag warned;
            if (!warned.test_and_set())
                spdlog::warn("runtimes: JVM release open returned STATUS_INVALID_PARAMETER or "
                             "NtCreateFile is unavailable -- OBJ_DONT_REPARSE unsupported on this "
                             "Windows build? every JVM release file reads as unreadable");
            return std::nullopt;
        }
        if (opened.status != yuzu::win::NoReparseOpen::ok) return std::nullopt;
        const HANDLE file = opened.file.get();
        BY_HANDLE_FILE_INFORMATION info{};
        if (!GetFileInformationByHandle(file, &info) ||
            (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) ||
            GetFileType(file) != FILE_TYPE_DISK)
            return std::nullopt;
        const std::uint64_t size =
            (static_cast<std::uint64_t>(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
        if (size > cap) return std::nullopt;
        std::string out(static_cast<std::size_t>(size), '\0');
        std::size_t got = 0;
        while (got < out.size()) {
            DWORD n = 0;
            if (!ReadFile(file, out.data() + got, static_cast<DWORD>(out.size() - got), &n,
                          nullptr) ||
                n == 0)
                return std::nullopt; // failed, or the file shrank under the read
            got += n;
        }
        return out;
    }
};

namespace detail {

[[nodiscard]] inline std::string_view open_token(LSTATUS rc) noexcept {
    return rc == ERROR_ACCESS_DENIED ? kTokAccessDenied : kTokOpenFailed;
}

[[nodiscard]] inline bool is_absent(LSTATUS rc) noexcept {
    return rc == ERROR_FILE_NOT_FOUND || rc == ERROR_PATH_NOT_FOUND;
}

/// Closes through `ops`, so a fake's handles never reach RegCloseKey. Owns a raw HKEY, so it is not
/// copyable (a copy would close the handle twice); a null handle (an open that was skipped) is a no-op.
template <class Ops>
struct KeyGuard {
    const Ops& ops;
    HKEY h = nullptr;
    KeyGuard(const Ops& o, HKEY k) noexcept : ops(o), h(k) {}
    KeyGuard(const KeyGuard&) = delete;
    ~KeyGuard() {
        if (h) ops.close(h);
    }
};

/// The shared bookkeeping of the dotnet / jvm walks: one visit counter across every enumerated
/// subkey and value (an over-long name counts too, so a key stuffed with them ends at the cap), and
/// the failure tokens. Absent is silent; any other failure is a token.
template <class Ops>
class RegWalk {
  public:
    RegWalk(const Ops& ops, yuzu::shared::ConstraintAccumulator& acc, const RegTokens& tok)
        : ops_(ops), acc_(acc), tok_(tok) {}

    [[nodiscard]] bool capped() const noexcept { return capped_; }

    /// True when `out` is an open key the caller must close.
    [[nodiscard]] bool open(HKEY parent, const wchar_t* sub, REGSAM sam, HKEY* out) {
        const LSTATUS rc = ops_.open(parent, sub, sam, out);
        if (rc == ERROR_SUCCESS) return true;
        if (!is_absent(rc))
            acc_.add_failure(rc == ERROR_ACCESS_DENIED ? tok_.access_denied : tok_.open_failed);
        return false;
    }

    /// `f(const wchar_t* name, int name_len)` for every subkey of `key`.
    template <class F>
    void each_subkey(HKEY key, F&& f) {
        wchar_t name[kNameLen]{};
        for (DWORD idx = 0; !capped_; ++idx) {
            DWORD name_len = kNameLen;
            const LSTATUS rc = ops_.enum_key(key, idx, name, &name_len);
            if (!step(rc)) return;
            if (rc == ERROR_MORE_DATA) continue;
            f(static_cast<const wchar_t*>(name), static_cast<int>(name_len));
        }
    }

    /// `f(const wchar_t* name, int name_len, const std::string& data)` for every value of `key`
    /// (`data` is empty for anything but a string value).
    template <class F>
    void each_value(HKEY key, F&& f) {
        wchar_t name[kNameLen]{};
        std::string data;
        for (DWORD idx = 0; !capped_; ++idx) {
            DWORD name_len = kNameLen;
            const LSTATUS rc = ops_.enum_value(key, idx, name, &name_len, &data);
            if (!step(rc)) return;
            if (rc == ERROR_MORE_DATA) continue;
            f(static_cast<const wchar_t*>(name), static_cast<int>(name_len), data);
        }
    }

  private:
    static constexpr DWORD kNameLen = 256; // WCHAR count, the unit the enumeration calls use

    /// False when the enumeration is over (end, error or cap); an over-long name is recorded.
    bool step(LSTATUS rc) {
        if (rc == ERROR_NO_MORE_ITEMS) return false;
        if (rc != ERROR_SUCCESS && rc != ERROR_MORE_DATA) {
            acc_.add_failure(tok_.enum_failed);
            return false;
        }
        if (++visited_ > kMaxEntriesVisited) {
            acc_.add_failure(tok_.row_cap);
            capped_ = true;
            return false;
        }
        if (rc == ERROR_MORE_DATA) acc_.add_failure(tok_.name_too_long);
        return true;
    }

    const Ops& ops_;
    yuzu::shared::ConstraintAccumulator& acc_;
    const RegTokens& tok_;
    std::size_t visited_ = 0;
    bool capped_ = false;
};

} // namespace detail

/// The python rows of this host: both views of HKLM\SOFTWARE\Python\PythonCore, failures in `acc`.
/// `root` / `subkey` are parameters only so the unit suite can point the real registry calls at an
/// isolated scratch key; production uses the defaults and never opens HKCU or a user hive.
template <class Ops>
[[nodiscard]] std::vector<std::string> python_rows(
    const Ops& ops, yuzu::shared::ConstraintAccumulator& acc, HKEY root = HKEY_LOCAL_MACHINE,
    const wchar_t* subkey = L"SOFTWARE\\Python\\PythonCore") {
    using Guard = detail::KeyGuard<Ops>;
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
            if (++tags_seen > kMaxEntriesVisited) {
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
    yuzu::shared::RowByteBudget budget{kMaxEntriesVisited, kMaxRowBytes};
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

// -- dotnet -------------------------------------------------------------------------------------

/// The key locations of the dotnet walk. Production uses the defaults; the unit suite points the real
/// registry calls at an isolated scratch key.
struct DotnetKeys {
    const wchar_t* installed_versions = L"SOFTWARE\\dotnet\\Setup\\InstalledVersions";
    const wchar_t* ndp_v4_full = L"SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full";
    const wchar_t* ndp_v35 = L"SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v3.5";
};

/// The dotnet rows of this host, both views of each key, failures in `acc`.
template <class Ops>
[[nodiscard]] std::vector<std::string> dotnet_rows(const Ops& ops,
                                                   yuzu::shared::ConstraintAccumulator& acc,
                                                   HKEY root = HKEY_LOCAL_MACHINE,
                                                   const DotnetKeys& keys = {}) {
    using Guard = detail::KeyGuard<Ops>;
    detail::RegWalk<Ops> walk{ops, acc, kDotnetTokens};
    std::vector<std::string> rows;
    for (const REGSAM view : {KEY_WOW64_64KEY, KEY_WOW64_32KEY}) {
        if (walk.capped()) break;
        // InstalledVersions\<arch>\{sharedfx\<framework>, sdk}: one row per value.
        HKEY versions = nullptr;
        if (walk.open(root, keys.installed_versions, KEY_READ | KEY_ENUMERATE_SUB_KEYS | view,
                      &versions)) {
            Guard versions_guard{ops, versions};
            walk.each_subkey(versions, [&](const wchar_t* arch, int) {
                HKEY arch_key = nullptr;
                if (!walk.open(versions, arch, KEY_READ | KEY_ENUMERATE_SUB_KEYS | view, &arch_key))
                    return;
                Guard arch_guard{ops, arch_key};
                // The value data is a path only when the installer wrote text; the .NET installers
                // write a DWORD 1, and the arch key's InstallLocation says where the tree is.
                const std::string install_location = ops.read_str(arch_key, L"InstallLocation");
                const auto read_values = [&](HKEY parent, const wchar_t* sub,
                                             std::string_view flavour) {
                    HKEY values = nullptr;
                    if (!walk.open(parent, sub, KEY_READ | view, &values)) return;
                    Guard values_guard{ops, values};
                    walk.each_value(values, [&](const wchar_t* name, int name_len,
                                                const std::string& data) {
                        const std::string version = yuzu::win::from_wide(name, name_len);
                        if (version.empty()) return; // the key's default value is not a version
                        rows.push_back(dotnet_registry_row(
                            flavour, dotnet_version_from_value_name(version),
                            data.empty() ? install_location : data));
                    });
                };
                read_values(arch_key, L"sdk", kFlavourSdk);
                HKEY sharedfx = nullptr;
                if (!walk.open(arch_key, L"sharedfx", KEY_READ | KEY_ENUMERATE_SUB_KEYS | view,
                               &sharedfx))
                    return;
                Guard sharedfx_guard{ops, sharedfx};
                walk.each_subkey(sharedfx, [&](const wchar_t* framework, int) {
                    read_values(sharedfx, framework, kFlavourRuntime);
                });
            });
        }
        // .NET Framework: NDP\v4\Full `Release` through the fixed table, NDP\v3.5 `Version`. An
        // `Install` value that is present and not 1 is a leftover key, not an install.
        const auto netfx = [&](const wchar_t* key_path, bool v4) {
            HKEY key = nullptr;
            if (!walk.open(root, key_path, KEY_READ | view, &key)) return;
            Guard key_guard{ops, key};
            if (const auto installed = ops.read_dword(key, L"Install"); installed && *installed != 1)
                return;
            std::string version;
            if (v4) {
                if (const auto release = ops.read_dword(key, L"Release"))
                    version = std::string{netfx_version_from_release(*release)};
            } else {
                version = ops.read_str(key, L"Version");
            }
            rows.push_back(dotnet_registry_row(kFlavourNetfx, version,
                                               ops.read_str(key, L"InstallPath")));
        };
        netfx(keys.ndp_v4_full, true);
        netfx(keys.ndp_v35, false);
    }
    return finish_rows(std::move(rows), acc, kDotnetTokens.row_cap);
}

// -- jvm ----------------------------------------------------------------------------------------

/// Where a vendor registers a home: <base>\<version>[\<tail>] holds `value` = the home directory.
struct JvmSource {
    const wchar_t* base;
    const wchar_t* tail; // "" = the version key itself
    const wchar_t* value;
};

inline constexpr JvmSource kJvmSources[] = {
    {L"SOFTWARE\\JavaSoft\\JDK", L"", L"JavaHome"},
    {L"SOFTWARE\\JavaSoft\\Java Development Kit", L"", L"JavaHome"},
    {L"SOFTWARE\\JavaSoft\\Java Runtime Environment", L"", L"JavaHome"},
    {L"SOFTWARE\\JavaSoft\\JRE", L"", L"JavaHome"},
    {L"SOFTWARE\\Eclipse Adoptium\\JDK", L"hotspot\\MSI", L"Path"},
    {L"SOFTWARE\\Eclipse Adoptium\\JRE", L"hotspot\\MSI", L"Path"},
    {L"SOFTWARE\\Azul Systems\\Zulu", L"", L"InstallationPath"},
    // Microsoft Build of OpenJDK registers HKLM\SOFTWARE\Microsoft\JDK\<ver>\hotspot\MSI `Path`.
    {L"SOFTWARE\\Microsoft\\JDK", L"hotspot\\MSI", L"Path"},
};

/// The jvm rows of this host: every registered home (both views, one per home path), each with one
/// bounded `release` read. A home whose release exists but is not readable is a row and a token.
template <class Ops>
[[nodiscard]] std::vector<std::string> jvm_rows(const Ops& ops,
                                                yuzu::shared::ConstraintAccumulator& acc,
                                                HKEY root = HKEY_LOCAL_MACHINE) {
    using Guard = detail::KeyGuard<Ops>;
    detail::RegWalk<Ops> walk{ops, acc, kJvmTokens};
    std::vector<JvmHome> homes;
    for (const REGSAM view : {KEY_WOW64_64KEY, KEY_WOW64_32KEY}) {
        for (const JvmSource& src : kJvmSources) {
            if (walk.capped()) break;
            HKEY base = nullptr;
            if (!walk.open(root, src.base, KEY_READ | KEY_ENUMERATE_SUB_KEYS | view, &base))
                continue;
            Guard base_guard{ops, base};
            walk.each_subkey(base, [&](const wchar_t* version, int version_len) {
                HKEY version_key = nullptr;
                if (!walk.open(base, version, KEY_READ | view, &version_key)) return;
                Guard version_guard{ops, version_key};
                HKEY tail_key = nullptr;
                if (*src.tail && !walk.open(version_key, src.tail, KEY_READ | view, &tail_key))
                    return;
                Guard tail_guard{ops, tail_key};
                const HKEY home_key = tail_key ? tail_key : version_key;
                std::string home = ops.read_str(home_key, src.value);
                if (home.empty() && ops.has_value(home_key, src.value))
                    acc.add_failure(kTokJvmHomeUnusable);
                add_jvm_home(homes, std::move(home), yuzu::win::from_wide(version, version_len));
            });
        }
    }
    std::sort(homes.begin(), homes.end(),
              [](const JvmHome& a, const JvmHome& b) { return a.key < b.key; });
    std::vector<std::string> rows;
    for (const JvmHome& h : homes) {
        // A non-local path is not opened: unreadable, never read as absent.
        const std::optional<std::string> release =
            is_local_drive_path(h.home)
                ? ops.read_file_bounded(yuzu::win::to_wide(jvm_release_path(h.home)),
                                        kMaxReleaseBytes)
                : std::nullopt;
        if (!release) acc.add_failure(kTokJvmReleaseUnreadable);
        rows.push_back(jvm_home_row(h, release));
    }
    return finish_rows(std::move(rows), acc, kJvmTokens.row_cap);
}

/// The Windows leg body over an ops seam: all three actions are registry reads.
template <class Ops>
int run_windows_with(yuzu::CommandContext& ctx, Action a, const Ops& ops) {
    yuzu::shared::ConstraintAccumulator acc;
    std::vector<std::string> rows;
    switch (a) {
    case Action::dotnet: rows = dotnet_rows(ops, acc); break;
    case Action::jvm:    rows = jvm_rows(ops, acc); break;
    case Action::python: rows = python_rows(ops, acc); break;
    }
    emit_read(ctx, a, rows, acc);
    return 0;
}

} // namespace yuzu::runtimes::win

#endif // _WIN32
