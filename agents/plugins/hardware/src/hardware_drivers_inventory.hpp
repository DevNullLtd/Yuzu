#pragma once

// hardware_drivers_inventory.hpp -- the pure core of the `drivers_inventory` action in
// hardware_plugin.cpp, plus the Linux read shell over agents/shared/posix_secure_read.hpp.
//
// ROW SCHEMA (ten pipe-separated fields, "-" for every absent value, never an "unknown" guess):
//
//   status|drivers_inventory|<supported|constrained|unsupported>|<tokens or ->     (always first)
//   driver_inv|<name>|<version>|<date>|<provider>|<class>|<signer>|<signed>|<inf>|<hwid>
//
// `<signed>` is signed | unsigned | "-". Every field goes through yuzu::util::safe_output_field,
// which is documented lossy (a '\' folds to '/', so a Windows hardware id such as
// `ACPI\VEN_PNP&DEV_0C0C` is written `ACPI/VEN_PNP&DEV_0C0C`).
//
// WHAT EACH LEG FILLS
//   Windows: all nine fields from Win32_PnPSignedDriver. Many rows (devices with no driver bound,
//     e.g. 'ACP HDA Node') carry only a HardWareID; every other field is "-".
//   Linux:   name from /proc/modules, version from /sys/module/<m>/version, signed from the
//     per-module taint flags (`E` = an unsigned module was loaded -> "unsigned"; anything else
//     proves nothing, so "-", never "signed"). Provider "kernel" and class "module" are the
//     literals the existing `drivers` action already uses. Date, signer, INF and hardware id have
//     no Linux source and are "-".
//   macOS:   no public kext/dext enumeration API; one unsupported status row, no data rows.
//
// compose() is the only place rows are ordered, deduplicated and formatted, so both legs and the
// tests share one definition. Everything here except read_linux() is platform-agnostic and
// OS-call-free, so it compiles and runs in the unit suite on every host. read_linux() is the thin
// POSIX shell (compiled out on Windows).
//
// Included as `hardware_drivers_inventory.hpp`; shared headers are found through the plugin's
// `../../shared` include directory.

#include <constraint_accumulator.hpp>
#include <inventory_status_row.hpp>

#include <yuzu/string_utils.hpp>

#include <algorithm>
#include <cstddef>
#include <map>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

#if !defined(_WIN32)
#include <cerrno>

#include <posix_secure_read.hpp>
#endif

namespace yuzu::hardware::drivers_inventory {

inline constexpr std::string_view kAction = "drivers_inventory";
inline constexpr std::string_view kRowTag = "driver_inv";

/// Most rows one run reports, on either leg. A WMI enumeration or a /proc/modules walk that
/// reaches it stops and says so (row_cap token); the default 512-row WMI cap truncates real hosts.
inline constexpr std::size_t kRowCap = 4096;
/// /proc/modules read bound (4096 lines of ~100 bytes is well under it).
inline constexpr std::size_t kProcModulesCap = 1024 * 1024;
/// Bound on each /sys/module/<m>/{version,taint} read.
inline constexpr std::size_t kSysfsFieldCap = 256;
inline constexpr std::size_t kModuleNameMax = 64;

// Reason tokens (status row field 4). The OS prefix keeps them unambiguous in a mixed fleet view.
inline constexpr std::string_view kLinuxRowCap = "linux:drivers_inventory:row_cap";
inline constexpr std::string_view kLinuxPermissionDenied = "linux:drivers_inventory:permission_denied";
inline constexpr std::string_view kLinuxInvalidName = "linux:drivers_inventory:invalid_module_name";
inline constexpr std::string_view kLinuxReadFailed = "linux:drivers_inventory:read_failed";
inline constexpr std::string_view kLinuxProcOversized = "linux:drivers_inventory:proc_modules_oversized";
inline constexpr std::string_view kWindowsRowCap = "windows:drivers_inventory:row_cap";
inline constexpr std::string_view kWindowsPrefix = "windows:drivers_inventory:"; // + wmi error token
inline constexpr std::string_view kMacosUnsupported = "macos:no_enumeration_api";

/// One driver. Every field is already "-"-normalised once it has passed through normalise().
struct Row {
    std::string name, version, date, provider, device_class, signer, signed_state, inf, hwid;
};

// ── field helpers (pure) ──────────────────────────────────────────────────────────────────

/// Trims ASCII whitespace (including NUL, which a fixed-width WMI/sysfs value can carry); an
/// empty result is "-".
[[nodiscard]] inline std::string normalise_field(std::string_view v) {
    constexpr std::string_view ws = " \t\r\n\v\f";
    while (!v.empty() && (ws.find(v.front()) != std::string_view::npos || v.front() == '\0'))
        v.remove_prefix(1);
    while (!v.empty() && (ws.find(v.back()) != std::string_view::npos || v.back() == '\0'))
        v.remove_suffix(1);
    return v.empty() ? std::string{"-"} : std::string{v};
}

namespace detail {
[[nodiscard]] constexpr bool all_digits(std::string_view s) noexcept {
    for (char c : s)
        if (c < '0' || c > '9')
            return false;
    return true;
}
} // namespace detail

/// A WMI CIM_DATETIME ("yyyymmddHHMMSS.mmmmmm+UUU") or an already-ISO "yyyy-mm-dd[...]" value as
/// "yyyy-mm-dd"; anything else is "-". The date is NEVER guessed from a locale form: the host
/// capture shows "21/06/2006 01:00:00", and dd/mm versus mm/dd cannot be told apart. Month 01-12 and
/// day 01-31 are range-checked so a garbage number is not published as a date.
[[nodiscard]] inline std::string date_to_iso(std::string_view raw) {
    std::string_view v = raw;
    while (!v.empty() && (v.front() == ' ' || v.front() == '\t'))
        v.remove_prefix(1);
    std::string y, m, d;
    if (v.size() >= 10 && v[4] == '-' && v[7] == '-' && detail::all_digits(v.substr(0, 4)) &&
        detail::all_digits(v.substr(5, 2)) && detail::all_digits(v.substr(8, 2))) {
        y = std::string{v.substr(0, 4)};
        m = std::string{v.substr(5, 2)};
        d = std::string{v.substr(8, 2)};
    } else if (v.size() >= 8 && detail::all_digits(v.substr(0, 8))) {
        y = std::string{v.substr(0, 4)};
        m = std::string{v.substr(4, 2)};
        d = std::string{v.substr(6, 2)};
    } else {
        return "-";
    }
    const int mi = std::stoi(m);
    const int di = std::stoi(d);
    if (mi < 1 || mi > 12 || di < 1 || di > 31 || y == "0000")
        return "-";
    return y + "-" + m + "-" + d;
}

/// Win32_PnPSignedDriver.IsSigned: the bounded WMI helper stringifies a boolean as true/false
/// (PowerShell prints True/False); case-insensitive. An empty or any other value is "-".
[[nodiscard]] inline std::string signed_from_wmi(std::string_view v) {
    std::string l;
    for (char c : v)
        if (c != ' ' && c != '\t')
            l += static_cast<char>(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
    if (l == "true")
        return "signed";
    if (l == "false")
        return "unsigned";
    return "-";
}

/// A Win32_PnPSignedDriver row (property name -> string, the bounded WMI helper's WmiRow shape).
[[nodiscard]] inline Row row_from_wmi(const std::map<std::string, std::string>& r) {
    const auto get = [&](const char* k) -> std::string {
        const auto it = r.find(k);
        return it == r.end() ? std::string{} : it->second;
    };
    Row out;
    out.name = normalise_field(get("DeviceName"));
    out.version = normalise_field(get("DriverVersion"));
    out.date = date_to_iso(get("DriverDate"));
    out.provider = normalise_field(get("DriverProviderName"));
    out.device_class = normalise_field(get("DeviceClass"));
    out.signer = normalise_field(get("Signer"));
    out.signed_state = signed_from_wmi(get("IsSigned"));
    out.inf = normalise_field(get("InfName"));
    out.hwid = normalise_field(get("HardWareID"));
    return out;
}

/// /sys/module/<m>/taint flag letters: `E` is TAINT_UNSIGNED_MODULE. Only that letter proves
/// anything, and only toward "unsigned": a module without the flag may be signed, or the kernel may
/// not enforce signatures at all, so the absence is "-" and never "signed".
[[nodiscard]] inline std::string signed_from_taint(std::string_view taint) {
    return taint.find('E') != std::string_view::npos ? "unsigned" : "-";
}

/// [A-Za-z0-9_-]{1,64}: the kernel's module-name alphabet. The name is later used as one openat()
/// hop under /sys/module, so anything else (a '/', "..") must never reach it.
[[nodiscard]] constexpr bool valid_module_name(std::string_view n) noexcept {
    if (n.empty() || n.size() > kModuleNameMax)
        return false;
    for (char c : n) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                        c == '_' || c == '-';
        if (!ok)
            return false;
    }
    return true;
}

// ── compose (pure; both legs) ─────────────────────────────────────────────────────────────

struct Composed {
    std::vector<std::string> lines; ///< status row first, then the data rows
    bool constrained = false;       ///< set_result_status CONSTRAINED/PARTIAL, else OK/FULL
    std::string tokens;             ///< comma-joined reason tokens ("" when none)
};

/// Sanitises every field (yuzu::util::safe_output_field), orders `rows` by (name, inf, hwid, version)
/// -- then by the remaining fields so the order is total and identical on every run -- drops exact
/// duplicates, formats them, and puts the status row first. `acc` carries every failure token the
/// leg recorded: any failure is `constrained`, and a leg that read nothing at all is therefore never
/// reported as an empty supported answer.
[[nodiscard]] inline Composed compose(std::vector<Row> rows,
                                      const yuzu::shared::ConstraintAccumulator& acc) {
    // Normalise and sanitise BEFORE ordering, so the published order is the order of the published
    // bytes (a backslash folds to '/', a '|' gains an escape: sorting the raw text could disagree).
    const auto clean = [](std::string& v) {
        v = yuzu::util::safe_output_field(normalise_field(v));
    };
    for (auto& r : rows)
        for (std::string* v : {&r.name, &r.version, &r.date, &r.provider, &r.device_class, &r.signer,
                               &r.signed_state, &r.inf, &r.hwid})
            clean(*v);
    const auto key = [](const Row& r) {
        return std::tie(r.name, r.inf, r.hwid, r.version, r.date, r.provider, r.device_class,
                        r.signer, r.signed_state);
    };
    std::sort(rows.begin(), rows.end(),
              [&](const Row& a, const Row& b) { return key(a) < key(b); });
    rows.erase(std::unique(rows.begin(), rows.end(),
                           [&](const Row& a, const Row& b) { return key(a) == key(b); }),
               rows.end());

    Composed out;
    out.constrained = acc.any_failure();
    out.tokens = acc.reason();
    out.lines.reserve(rows.size() + 1);
    out.lines.push_back(yuzu::shared::format_status_row(
        kAction,
        out.constrained ? yuzu::shared::StatusLevel::constrained
                        : yuzu::shared::StatusLevel::supported,
        out.tokens));
    for (const auto& r : rows) {
        std::string line{kRowTag};
        for (const std::string* s : {&r.name, &r.version, &r.date, &r.provider, &r.device_class,
                                     &r.signer, &r.signed_state, &r.inf, &r.hwid}) {
            line += '|';
            line += *s;
        }
        out.lines.push_back(std::move(line));
    }
    return out;
}

/// The macOS answer: one unsupported status row, no data rows.
[[nodiscard]] inline std::string unsupported_line(std::string_view token) {
    return yuzu::shared::format_status_row(kAction, yuzu::shared::StatusLevel::unsupported, token);
}

// ── Linux collection (pure over an injected sysfs reader) ─────────────────────────────────

/// One sysfs attribute read. `absent` (ENOENT) is a normal answer ("-"); `denied` and `failed` are
/// recorded as constraint tokens.
struct SysRead {
    enum class Status { ok, absent, denied, failed };
    Status status = Status::absent;
    std::string data;
};
struct ModuleAttrs {
    SysRead version, taint;
};

/// Parses /proc/modules text (first whitespace-delimited token per line is the module name) and
/// builds one Row per valid module. `reader(name) -> ModuleAttrs` supplies the per-module sysfs
/// attributes. An invalid name is skipped with kLinuxInvalidName; reaching `cap` valid modules
/// stops the walk with kLinuxRowCap.
template <class Reader>
[[nodiscard]] std::vector<Row> collect_linux_rows(std::string_view proc_modules, Reader&& reader,
                                                  yuzu::shared::ConstraintAccumulator& acc,
                                                  std::size_t cap = kRowCap) {
    std::vector<Row> rows;
    std::size_t pos = 0;
    while (pos < proc_modules.size()) {
        std::size_t eol = proc_modules.find('\n', pos);
        if (eol == std::string_view::npos)
            eol = proc_modules.size();
        std::string_view line = proc_modules.substr(pos, eol - pos);
        pos = eol + 1;
        const std::size_t sp = line.find_first_of(" \t");
        const std::string_view name = line.substr(0, sp);
        if (name.empty())
            continue;
        if (!valid_module_name(name)) {
            acc.add_failure(kLinuxInvalidName);
            continue;
        }
        if (rows.size() >= cap) {
            acc.add_failure(kLinuxRowCap);
            break;
        }
        const ModuleAttrs attrs = reader(name);
        Row r;
        r.name = std::string{name};
        r.provider = "kernel";
        r.device_class = "module";
        const auto note = [&](const SysRead& s) {
            if (s.status == SysRead::Status::denied)
                acc.add_failure(kLinuxPermissionDenied);
            else if (s.status == SysRead::Status::failed)
                acc.add_failure(kLinuxReadFailed);
        };
        note(attrs.version);
        note(attrs.taint);
        r.version = attrs.version.status == SysRead::Status::ok ? attrs.version.data : "";
        r.signed_state = attrs.taint.status == SysRead::Status::ok
                             ? signed_from_taint(attrs.taint.data)
                             : "";
        r.date = r.signer = r.inf = r.hwid = "";
        rows.push_back(std::move(r));
    }
    return rows;
}

// ── Linux shell (POSIX only) ──────────────────────────────────────────────────────────────

#if !defined(_WIN32)
namespace detail {
[[nodiscard]] inline SysRead::Status status_from_errno(int e) noexcept {
    if (e == ENOENT || e == ENOTDIR)
        return SysRead::Status::absent;
    if (e == EACCES || e == EPERM)
        return SysRead::Status::denied;
    return SysRead::Status::failed;
}

[[nodiscard]] inline SysRead sys_read(const yuzu::shared::FileRead& fr) {
    SysRead out;
    if (fr.ok()) {
        out.status = SysRead::Status::ok;
        out.data = fr.data;
    } else if (fr.error == yuzu::shared::ReadError::io) {
        out.status = status_from_errno(fr.err);
    } else {
        out.status = SysRead::Status::failed; // symlink_refused / not_regular / oversized
    }
    return out;
}
} // namespace detail

/// Reads `proc_modules_path` (bounded, no-follow leaf) and, under one opened `sys_module_dir`
/// descriptor, `<m>/version` and `<m>/taint` for each module (one openat hop per component, each
/// read capped at kSysfsFieldCap, no symlink followed). Production: "/proc/modules", "/sys/module".
/// A failed /proc/modules read returns no rows and records why, so the caller reports constrained,
/// never an empty supported answer.
[[nodiscard]] inline std::vector<Row> read_linux(const std::string& proc_modules_path,
                                                 const std::string& sys_module_dir,
                                                 yuzu::shared::ConstraintAccumulator& acc,
                                                 std::size_t cap = kRowCap) {
    const auto proc = yuzu::shared::read_file_no_follow(proc_modules_path, kProcModulesCap);
    if (!proc.ok()) {
        if (proc.error == yuzu::shared::ReadError::oversized)
            acc.add_failure(kLinuxProcOversized);
        else if (proc.error == yuzu::shared::ReadError::io &&
                 detail::status_from_errno(proc.err) == SysRead::Status::denied)
            acc.add_failure(kLinuxPermissionDenied);
        else
            acc.add_failure(kLinuxReadFailed);
        return {};
    }

    const auto root = yuzu::shared::open_dir_no_follow(sys_module_dir);
    const SysRead::Status root_status =
        root.opened() ? SysRead::Status::ok : detail::status_from_errno(root.err);
    // A missing /sys/module with a populated /proc/modules is not a normal host: report it, do not
    // let every version/signed cell silently read "-".
    const SysRead::Status root_failure =
        root_status == SysRead::Status::absent ? SysRead::Status::failed : root_status;

    const auto reader = [&](std::string_view module) -> ModuleAttrs {
        ModuleAttrs a;
        if (!root.opened()) {
            a.version.status = a.taint.status = root_failure;
            return a;
        }
        const std::string m{module};
        const auto md = yuzu::shared::open_dir_no_follow_at(root.dir.fd(), m.c_str());
        if (!md.opened()) {
            a.version.status = a.taint.status = detail::status_from_errno(md.err);
            return a;
        }
        a.version = detail::sys_read(
            yuzu::shared::read_file_no_follow_at(md.dir.fd(), "version", kSysfsFieldCap));
        a.taint = detail::sys_read(
            yuzu::shared::read_file_no_follow_at(md.dir.fd(), "taint", kSysfsFieldCap));
        return a;
    };
    return collect_linux_rows(proc.data, reader, acc, cap);
}
#endif // !_WIN32

} // namespace yuzu::hardware::drivers_inventory
