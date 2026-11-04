/**
 * pkg_inventory_win_parsers.hpp -- the Windows legs of pkg_inventory: the Appx
 * `store_packages` roster, Chocolatey `packages`, and Chocolatey / winget presence
 * in `managers`.
 *
 * SHAPE. Everything that decides anything is a pure template over an injected ops
 * seam (`Ops`) built from portable types only, so it compiles and is unit-tested
 * on EVERY OS by test_pkg_inventory_win_parsers.cpp over a FakeOps. Only `RealOps`
 * (bottom of the file, `#ifdef _WIN32`) touches the OS: the registry (Reg*W), a
 * single-level directory listing (FindFirstFileExW) and one bounded file read.
 * Nothing spawns a process: no choco.exe, no winget.exe.
 *
 * WHAT IS READ (every mechanism below was captured on a real host, 2026-11-04;
 * the captures are summarised in docs/samples/windows.txt and the README):
 *   store_packages  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore
 *                   \{Applications, InboxApplications, Deprovisioned}: one subkey
 *                   per PackageFullName (Name_Version_Arch_ResourceId_PublisherId).
 *                   Per-user SID subkeys are never enumerated (machine scope).
 *                   A missing key (Deprovisioned was absent on the capture host) is
 *                   normal; a denied key is a constraint. The WindowsApps folder is
 *                   deliberately NOT listed (its ACL denies the agent's service
 *                   account the listing) and AppxManifest.xml is never read, so
 *                   there is no publisher column.
 *   packages        C:\ProgramData\chocolatey\lib\<id>\<id>.nuspec, one bounded
 *                   read per package; <version> by a bounded tag scan (no libxml2).
 *                   The directory name is the id. A directory with no loose nuspec
 *                   is not a roster entry: the chocolatey bootstrap package is one
 *                   (captured: its directory holds only chocolatey.nupkg), and its
 *                   presence is the `managers` row.
 *   managers        chocolatey: the lib directory is listable (present, with the
 *                   directory count). winget: a Microsoft.DesktopAppInstaller_*
 *                   key under Applications (version from the key name, root from
 *                   its `Path` value). Chocolatey's own version is NOT read: the
 *                   bootstrap package has no loose nuspec and bin\choco.exe is a
 *                   shim that reports the shim's version (captured 0.12.1, while
 *                   `choco list` said 2.7.5), so the version column is `-`.
 *
 * FAILURE NEVER READS AS ABSENT. An absent root is silent (supported, zero rows /
 * no manager row). A denied or failing roster key, lib listing or manager probe is
 * a `windows:pkg_inventory:<source>:<cause>` token (CONSTRAINED). Per-item
 * shortfalls (an unreadable nuspec, an unparsable package name) degrade the ROW
 * (`-`), never the action, because the installed-software collector fails a
 * constrained `packages` / `store_packages` answer and a persistent per-item
 * anomaly must not wedge the sync (pkg_inventory_parsers.hpp "TWO TOKEN CLASSES").
 *
 * BOUNDED. 4096 roster keys per store key, 2048 lib directories, one RowByteBudget
 * (kMaxPackageRows rows, kMaxOutputBytes bytes), a 64 KiB nuspec read.
 */
#pragma once

#include "pkg_inventory_legs.hpp"
#include "pkg_inventory_parsers.hpp"

#include <constraint_accumulator.hpp>
#include <row_byte_budget.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <win_bounded_file_read.hpp>
#include <win_reg_handle.hpp>
#include <win_str.hpp>
#endif

namespace yuzu::pkg_inventory::win {

// ── limits ───────────────────────────────────────────────────────────────

/// Largest value the tag scanner will return (a version string is tens of bytes).
inline constexpr std::size_t kMaxXmlValueBytes = 4096;
/// Bytes read from one nuspec (captured files are 1.1-5.5 KB).
inline constexpr std::size_t kMaxNuspecBytes = 64 * 1024;
/// Longest version string a row will carry; longer reads as unknown (`-`).
inline constexpr std::size_t kMaxVersionBytes = 128;

struct WinLimits {
    std::size_t max_roster_keys = kMaxEntriesPerDir; ///< per Appx store key
    std::size_t max_lib_entries = 2048;              ///< chocolatey lib directories
    std::size_t max_rows = kMaxPackageRows;
    std::size_t max_output_bytes = kMaxOutputBytes;
    std::size_t max_nuspec_bytes = kMaxNuspecBytes;
};

// ── fixed locations (literals; the seam takes them as arguments) ─────────

inline constexpr std::string_view kChocolateyRoot = "C:\\ProgramData\\chocolatey";
inline constexpr std::string_view kChocolateyLib = "C:\\ProgramData\\chocolatey\\lib";
inline constexpr std::string_view kWingetPackageName = "Microsoft.DesktopAppInstaller";

// ── pure: bounded tag scanner (nuspec) ───────────────────────────────────

namespace detail {

[[nodiscard]] constexpr char ascii_lower(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}
[[nodiscard]] constexpr bool is_xml_ws(char c) noexcept {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}
[[nodiscard]] inline bool ieq(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i)
        if (ascii_lower(a[i]) != ascii_lower(b[i])) return false;
    return true;
}

/// Trims XML whitespace and refuses anything with an `&` in it (an entity or numeric
/// reference is never decoded, never guessed: the one caller reads a version token,
/// which has none). nullopt for an empty or over-long value.
[[nodiscard]] inline std::optional<std::string> decode_xml_text(std::string_view raw) {
    while (!raw.empty() && is_xml_ws(raw.front())) raw.remove_prefix(1);
    while (!raw.empty() && is_xml_ws(raw.back())) raw.remove_suffix(1);
    if (raw.empty() || raw.size() > kMaxXmlValueBytes || raw.find('&') != std::string_view::npos)
        return std::nullopt;
    return std::string{raw};
}

} // namespace detail

/// The text of the FIRST `<tag>text</tag>` element in `xml` (tag name matched ASCII
/// case-insensitively), or nullopt. Comments, CDATA sections, processing
/// instructions and `<!...>` declarations are skipped, so markup quoted inside
/// them never counts. The element must hold plain text closed by its own end tag;
/// an empty element, one holding child markup or CDATA, a value containing any `&`
/// (entities are not decoded), an empty value and one over kMaxXmlValueBytes all read
/// as nullopt -- the scanner returns what the file says or nothing, never a guess.
[[nodiscard]] inline std::optional<std::string> extract_xml_text(std::string_view xml,
                                                                 std::string_view tag) {
    std::size_t pos = 0;
    while (pos < xml.size()) {
        pos = xml.find('<', pos);
        if (pos == std::string_view::npos) return std::nullopt;
        const auto rest = xml.substr(pos);
        const auto skip_to = [&](std::string_view open, std::string_view close) {
            if (!rest.starts_with(open)) return false;
            const auto e = xml.find(close, pos + open.size());
            pos = e == std::string_view::npos ? xml.size() : e + close.size();
            return true;
        };
        if (skip_to("<!--", "-->") || skip_to("<![CDATA[", "]]>") || skip_to("<?", "?>"))
            continue;
        if (rest.starts_with("<!")) {
            const auto e = xml.find('>', pos);
            pos = e == std::string_view::npos ? xml.size() : e + 1;
            continue;
        }
        if (rest.starts_with("</")) {
            pos += 2;
            continue;
        }
        const std::size_t name_begin = pos + 1;
        std::size_t name_end = name_begin;
        while (name_end < xml.size() && !detail::is_xml_ws(xml[name_end]) && xml[name_end] != '>' &&
               xml[name_end] != '/')
            ++name_end;
        pos = name_end;
        if (!detail::ieq(xml.substr(name_begin, name_end - name_begin), tag)) continue;

        // The first matching start tag decides the answer.
        const auto gt = xml.find('>', name_end);
        if (gt == std::string_view::npos || xml[gt - 1] == '/') return std::nullopt;
        const auto lt = xml.find('<', gt + 1);
        if (lt == std::string_view::npos || !xml.substr(lt).starts_with("</")) return std::nullopt;
        std::size_t close_end = lt + 2;
        while (close_end < xml.size() && !detail::is_xml_ws(xml[close_end]) && xml[close_end] != '>')
            ++close_end;
        if (!detail::ieq(xml.substr(lt + 2, close_end - lt - 2), tag)) return std::nullopt;
        return detail::decode_xml_text(xml.substr(gt + 1, lt - gt - 1));
    }
    return std::nullopt;
}

/// A version string a row may carry: 1..kMaxVersionBytes printable ASCII, no
/// whitespace and no `|` or `\` (so it needs no escaping to stay one column).
[[nodiscard]] inline bool plausible_version(std::string_view v) noexcept {
    if (v.empty() || v.size() > kMaxVersionBytes) return false;
    return std::all_of(v.begin(), v.end(), [](char c) {
        const auto u = static_cast<unsigned char>(c);
        return u > 0x20 && u < 0x7f && c != '|' && c != '\\';
    });
}

// ── pure: Appx PackageFullName ───────────────────────────────────────────

/// The parts of `Name_Version_Arch_ResourceId_PublisherId` a row carries; views into
/// the parsed string. (ResourceId and PublisherId are validated, not kept.)
struct AppxName {
    std::string_view name;
    std::string_view version;
    std::string_view arch;
};

namespace detail {

[[nodiscard]] constexpr bool is_alnum(char c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}

} // namespace detail

/// Dotted-numeric version -> components (`^[0-9]{1,10}(\.[0-9]{1,10}){0,3}$`, so each
/// fits an unsigned long long), nullopt for anything else. The validator and the
/// ordering key for choosing the highest of several registered versions.
[[nodiscard]] inline std::optional<std::vector<unsigned long long>>
appx_version_parts(std::string_view v) {
    std::vector<unsigned long long> out;
    std::size_t start = 0;
    for (;;) {
        const auto dot = v.find('.', start);
        const auto part = v.substr(start, (dot == std::string_view::npos ? v.size() : dot) - start);
        if (part.empty() || part.size() > 10 || out.size() == 4) return std::nullopt;
        unsigned long long n = 0;
        for (const char c : part) {
            if (c < '0' || c > '9') return std::nullopt;
            n = n * 10 + static_cast<unsigned>(c - '0');
        }
        out.push_back(n);
        if (dot == std::string_view::npos) return out;
        start = dot + 1;
    }
}

/// Splits a PackageFullName on `_` into exactly five parts and validates each
/// (nothing here is trusted to be a clean column): a 4- or 6-part name, a name with
/// a character outside `[A-Za-z0-9.-]`, a malformed version, an arch outside
/// `[a-z0-9]{1,16}`, a resource id outside `[A-Za-z0-9~-]{0,64}` or a publisher id
/// outside `[a-z0-9]{1,16}` is nullopt. Pinned against the real names of a Windows 11
/// host, including GUID-prefixed inbox names, a `~` resource id (bundles) and an
/// empty resource id (`neutral__`).
[[nodiscard]] inline std::optional<AppxName> parse_package_full_name(std::string_view full) {
    if (full.empty() || full.size() > 255) return std::nullopt;
    std::array<std::string_view, 5> part{};
    std::size_t n = 0;
    std::size_t begin = 0;
    for (std::size_t i = 0; i <= full.size(); ++i) {
        if (i != full.size() && full[i] != '_') continue;
        if (n == part.size()) return std::nullopt;
        part[n++] = full.substr(begin, i - begin);
        begin = i + 1;
    }
    if (n != part.size()) return std::nullopt;
    const auto name = part[0];
    const auto version = part[1];
    const auto arch = part[2];
    const auto resource = part[3];
    const auto publisher = part[4];
    if (name.empty() || name.size() > 128 ||
        !std::all_of(name.begin(), name.end(),
                     [](char c) { return detail::is_alnum(c) || c == '.' || c == '-'; }))
        return std::nullopt;
    if (!appx_version_parts(version)) return std::nullopt;
    if (arch.empty() || arch.size() > 16 ||
        !std::all_of(arch.begin(), arch.end(),
                     [](char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'); }))
        return std::nullopt;
    if (resource.size() > 64 ||
        !std::all_of(resource.begin(), resource.end(),
                     [](char c) { return detail::is_alnum(c) || c == '~' || c == '-'; }))
        return std::nullopt;
    if (publisher.empty() || publisher.size() > 16 ||
        !std::all_of(publisher.begin(), publisher.end(),
                     [](char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'); }))
        return std::nullopt;
    return AppxName{name, version, arch};
}

/// The package folder named by a roster `Path` value: the value is a MANIFEST FILE
/// path (`...\<PackageFullName>\AppxManifest.xml`, or
/// `...\AppxMetadata\AppxBundleManifest.xml` for a bundle; captured), so the folder
/// is the path minus that tail. Empty when the value has neither shape.
[[nodiscard]] inline std::string_view appx_package_folder(std::string_view manifest_path) noexcept {
    for (const std::string_view tail :
         {std::string_view{"\\AppxMetadata\\AppxBundleManifest.xml"},
          std::string_view{"\\AppxManifest.xml"}}) {
        if (manifest_path.size() > tail.size() &&
            detail::ieq(manifest_path.substr(manifest_path.size() - tail.size()), tail))
            return manifest_path.substr(0, manifest_path.size() - tail.size());
    }
    return {};
}

// ── pure: rows ───────────────────────────────────────────────────────────

/// package|appx|<PackageFullName>|<version or ->|app|-|<arch or ->|-|<active|deprovisioned>
/// An unparsable key name is still a row (id = the key name as registered) with
/// version and arch `-`: the roster stays complete and the shortfall is visible.
[[nodiscard]] inline std::string appx_store_row(std::string_view key_name, StoreState state) {
    const auto p = parse_package_full_name(key_name);
    return format_store_row(Store::appx, key_name, p ? p->version : std::string_view{}, "app", "",
                            p ? p->arch : std::string_view{}, "", state);
}

/// package|chocolatey|<id>|<version or ->|pkg
[[nodiscard]] inline std::string chocolatey_package_row(std::string_view id,
                                                        std::string_view version) {
    return format_package_row(id, version, PackageKind::pkg, "chocolatey");
}

// ── tokens ───────────────────────────────────────────────────────────────

/// `windows:pkg_inventory:<source>:<cause>`
[[nodiscard]] inline std::string win_token(std::string_view source, std::string_view cause) {
    return make_token("windows", std::string{"pkg_inventory:"} + std::string{source}, cause);
}

// ── the ops seam (portable types) ────────────────────────────────────────

/// `absent` = the key/path/file is not there; `denied` = access refused; `error` =
/// anything else (including a refused reparse point or a directory read as a file).
enum class OpStatus { ok, absent, denied, error };

struct NameList {
    OpStatus status = OpStatus::ok;
    std::vector<std::string> names; ///< UTF-8, at most the requested cap
    bool truncated = false;         ///< more entries existed than the cap
    bool enum_failed = false;       ///< the enumeration stopped on an error mid-way
};
struct ValueRead {
    OpStatus status = OpStatus::ok;
    std::string value;
};
struct FileRead {
    OpStatus status = OpStatus::ok;
    std::string bytes; ///< at most the requested cap
};

// The seam a leg needs (RealOps below; FakeOps in the unit suite):
//   NameList list_reg_subkeys(std::string_view store_key, std::size_t cap) const;
//       subkey names of AppxAllUserStore\<store_key>
//   ValueRead read_reg_string(std::string_view store_key, std::string_view subkey,
//                             std::string_view value) const;
//       a REG_SZ value only (REG_EXPAND_SZ reads as `error`: no environment expansion is done)
//   NameList list_dir(std::string_view path, std::size_t cap) const;
//       the REAL (non-reparse) sub-DIRECTORY names of `path`, single level
//   FileRead read_file(std::string_view path, std::size_t cap) const;
//       the first min(size, cap) bytes of a regular file; a reparse point is `error`

namespace detail {

[[nodiscard]] inline std::string_view cause_of(OpStatus s) noexcept {
    return s == OpStatus::denied ? "access_denied" : "open_failed";
}

/// Folds one listing's outcome into `acc`. False when the names are unusable
/// (absent -- silent -- or a failed open), true when `list.names` may be used.
inline bool note_listing(yuzu::shared::ConstraintAccumulator& acc, std::string_view source,
                         const NameList& list) {
    if (list.status == OpStatus::absent) return false;
    if (list.status != OpStatus::ok) {
        acc.add_failure(win_token(source, cause_of(list.status)));
        acc.mark_incomplete();
        return false;
    }
    if (list.truncated) {
        acc.add_failure(win_token(source, "entry_cap"));
        acc.mark_incomplete();
    }
    if (list.enum_failed) {
        acc.add_failure(win_token(source, "enum_failed"));
        acc.mark_incomplete();
    }
    return true;
}

[[nodiscard]] inline bool charge_row(yuzu::shared::RowByteBudget& budget,
                                     yuzu::shared::ConstraintAccumulator& acc,
                                     std::string_view source, std::size_t row_bytes) {
    if (budget.charge(row_bytes + 1)) return true;
    acc.add_failure(win_token(source, budget.rows >= budget.max_rows ? "row_cap" : "byte_cap"));
    acc.mark_incomplete();
    return false;
}

struct RosterKey {
    std::string_view leaf;
    std::string_view source;
    StoreState state;
};
inline constexpr RosterKey kRosterKeys[] = {
    {"Applications", "appx_applications", StoreState::active},
    {"InboxApplications", "appx_inbox", StoreState::active},
    {"Deprovisioned", "appx_deprovisioned", StoreState::deprovisioned},
};

} // namespace detail

// ── the three legs ───────────────────────────────────────────────────────

/// `store_packages`: one row per subkey of the three roster keys, each key sorted.
template <class Ops>
[[nodiscard]] std::vector<std::string>
store_package_rows(const Ops& ops, yuzu::shared::ConstraintAccumulator& acc,
                   const WinLimits& lim = WinLimits{}) {
    std::vector<std::string> rows;
    yuzu::shared::RowByteBudget budget{lim.max_rows, lim.max_output_bytes};
    for (const auto& key : detail::kRosterKeys) {
        auto list = ops.list_reg_subkeys(key.leaf, lim.max_roster_keys);
        if (!detail::note_listing(acc, key.source, list)) continue;
        std::sort(list.names.begin(), list.names.end());
        for (const auto& name : list.names) {
            auto row = appx_store_row(name, key.state);
            if (!detail::charge_row(budget, acc, key.source, row.size())) return rows;
            rows.push_back(std::move(row));
        }
    }
    return rows;
}

/// `packages`: one row per chocolatey lib directory that holds a loose nuspec.
template <class Ops>
[[nodiscard]] std::vector<std::string>
chocolatey_package_rows(const Ops& ops, yuzu::shared::ConstraintAccumulator& acc,
                        const WinLimits& lim = WinLimits{}) {
    std::vector<std::string> rows;
    auto list = ops.list_dir(kChocolateyLib, lim.max_lib_entries);
    if (!detail::note_listing(acc, "chocolatey_lib", list)) return rows;
    std::sort(list.names.begin(), list.names.end());
    yuzu::shared::RowByteBudget budget{lim.max_rows, lim.max_output_bytes};
    for (const auto& dir : list.names) {
        std::string path{kChocolateyLib};
        path += '\\';
        path += dir;
        path += '\\';
        path += dir;
        path += ".nuspec";
        const auto file = ops.read_file(path, lim.max_nuspec_bytes);
        if (file.status == OpStatus::absent) continue; // no loose nuspec: not a roster entry
        std::string version;
        if (file.status == OpStatus::ok) {
            if (auto v = extract_xml_text(file.bytes, "version"); v && plausible_version(*v))
                version = std::move(*v);
        }
        auto row = chocolatey_package_row(dir, version);
        if (!detail::charge_row(budget, acc, "chocolatey_lib", row.size())) break;
        rows.push_back(std::move(row));
    }
    return rows;
}

/// `managers`: a chocolatey row when its lib directory is listable, a winget row
/// when the Appx roster carries the App Installer package. An absent manager has
/// no row; one that is there but unreadable is an `unavailable` row plus a token.
template <class Ops>
[[nodiscard]] std::vector<std::string>
manager_rows(const Ops& ops, yuzu::shared::ConstraintAccumulator& acc,
             const WinLimits& lim = WinLimits{}) {
    std::vector<std::string> rows;

    const auto lib = ops.list_dir(kChocolateyLib, lim.max_lib_entries);
    if (lib.status == OpStatus::ok) {
        detail::note_listing(acc, "chocolatey_lib", lib);
        Facts facts;
        if (!lib.truncated && !lib.enum_failed) facts.add("lib_dirs", lib.names.size());
        rows.push_back(format_manager_row(Manager::chocolatey, Presence::present, "",
                                          kChocolateyRoot, facts.str(), ""));
    } else if (lib.status != OpStatus::absent) {
        const auto token = win_token("chocolatey_lib", detail::cause_of(lib.status));
        acc.add_failure(token);
        acc.mark_incomplete();
        rows.push_back(format_manager_row(Manager::chocolatey, Presence::unavailable, "",
                                          kChocolateyRoot, "-", token));
    }

    constexpr std::string_view kApps = "Applications";
    const auto apps = ops.list_reg_subkeys(kApps, lim.max_roster_keys);
    if (apps.status == OpStatus::ok) {
        detail::note_listing(acc, "appx_applications", apps);
        std::optional<AppxName> best;
        const std::string* best_key = nullptr;
        std::vector<unsigned long long> best_ver;
        for (const auto& name : apps.names) {
            const auto p = parse_package_full_name(name);
            if (!p || p->name != kWingetPackageName) continue;
            auto ver = appx_version_parts(p->version).value(); // validated by the parse above
            if (!best || ver > best_ver) {
                best = p;
                best_key = &name;
                best_ver = std::move(ver);
            }
        }
        if (best) {
            std::string root;
            if (const auto path = ops.read_reg_string(kApps, *best_key, "Path");
                path.status == OpStatus::ok)
                root = std::string{appx_package_folder(path.value)};
            rows.push_back(format_manager_row(Manager::winget, Presence::present, best->version, root,
                                              "-", ""));
        }
    } else if (apps.status != OpStatus::absent) {
        const auto token = win_token("appx_applications", detail::cause_of(apps.status));
        acc.add_failure(token);
        acc.mark_incomplete();
        rows.push_back(
            format_manager_row(Manager::winget, Presence::unavailable, "", "", "-", token));
    }
    return rows;
}

/// The Windows leg body over an ops seam: rows + one constraint string into the
/// shared emission seam (status row first, then the CC-07 typed status).
template <class Ops>
int run_windows_with(yuzu::CommandContext& ctx, Action a, const Ops& ops,
                     const WinLimits& lim = WinLimits{}) {
    yuzu::shared::ConstraintAccumulator acc;
    std::vector<std::string> rows;
    switch (a) {
    case Action::managers: rows = manager_rows(ops, acc, lim); break;
    case Action::packages: rows = chocolatey_package_rows(ops, acc, lim); break;
    case Action::store_packages: rows = store_package_rows(ops, acc, lim); break;
    }
    emit_result(ctx, a, rows,
                acc.any_failure() ? std::optional<std::string>{acc.reason()} : std::nullopt);
    return 0;
}

// ── the real OS seam (Windows only; thin, no decisions) ──────────────────

#ifdef _WIN32

/// Registry (Reg*W), FindFirstFileExW and one bounded file read. `root` and
/// `appx_base` are parameters only so the unit suite can point the registry calls
/// at an isolated HKCU scratch key; production uses the defaults and reads HKLM
/// only (no per-user hive is ever opened).
class RealOps {
public:
    RealOps() = default;
    RealOps(HKEY root, std::wstring appx_base) : root_(root), appx_base_(std::move(appx_base)) {}

    [[nodiscard]] NameList list_reg_subkeys(std::string_view store_key, std::size_t cap) const {
        NameList out;
        yuzu::win::RegKey key;
        const LSTATUS rc = RegOpenKeyExW(root_, key_path(store_key).c_str(), 0,
                                         KEY_READ | KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY,
                                         key.put());
        if (rc != ERROR_SUCCESS) {
            out.status = status_of(rc);
            return out;
        }
        constexpr DWORD kNameLen = 256; // WCHARs; a registry key name is at most 255
        wchar_t name[kNameLen]{};
        for (DWORD idx = 0;; ++idx) {
            DWORD len = kNameLen;
            const LSTATUS erc = RegEnumKeyExW(key.get(), idx, name, &len, nullptr, nullptr, nullptr,
                                              nullptr);
            if (erc == ERROR_NO_MORE_ITEMS) break;
            if (erc != ERROR_SUCCESS) {
                out.enum_failed = true;
                break;
            }
            if (out.names.size() >= cap) {
                out.truncated = true;
                break;
            }
            out.names.push_back(yuzu::win::from_wide(name, static_cast<int>(len)));
        }
        return out;
    }

    [[nodiscard]] ValueRead read_reg_string(std::string_view store_key, std::string_view subkey,
                                            std::string_view value) const {
        ValueRead out;
        if (subkey.empty() || value.empty()) {
            out.status = OpStatus::error; // an empty name would open the parent / default value
            return out;
        }
        yuzu::win::RegKey key;
        const std::wstring path = key_path(store_key) + L"\\" + yuzu::win::to_wide(subkey);
        LSTATUS rc = RegOpenKeyExW(root_, path.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, key.put());
        if (rc != ERROR_SUCCESS) {
            out.status = status_of(rc);
            return out;
        }
        const std::wstring wvalue = yuzu::win::to_wide(value);
        DWORD type = 0;
        DWORD size = 0;
        rc = RegQueryValueExW(key.get(), wvalue.c_str(), nullptr, &type, nullptr, &size);
        if (rc != ERROR_SUCCESS) {
            out.status = status_of(rc);
            return out;
        }
        constexpr DWORD kMaxValueBytes = 64 * 1024;
        if (type != REG_SZ || size < sizeof(wchar_t) || size > kMaxValueBytes) {
            out.status = OpStatus::error;
            return out;
        }
        std::wstring buf(size / sizeof(wchar_t) + 1, L'\0');
        DWORD got = size;
        rc = RegQueryValueExW(key.get(), wvalue.c_str(), nullptr, &type,
                              reinterpret_cast<LPBYTE>(buf.data()), &got);
        if (rc != ERROR_SUCCESS) {
            out.status = OpStatus::error; // grew between the two reads, or vanished
            return out;
        }
        out.value = yuzu::win::reg_sz_to_utf8(buf.c_str(), got);
        return out;
    }

    [[nodiscard]] NameList list_dir(std::string_view path, std::size_t cap) const {
        NameList out;
        if (path.empty()) {
            out.status = OpStatus::error; // "\*" would list the current drive's root
            return out;
        }
        const std::wstring pattern = yuzu::win::to_wide(path) + L"\\*";
        WIN32_FIND_DATAW fd{};
        const HANDLE h = FindFirstFileExW(pattern.c_str(), FindExInfoBasic, &fd,
                                          FindExSearchNameMatch, nullptr,
                                          FIND_FIRST_EX_LARGE_FETCH);
        if (h == INVALID_HANDLE_VALUE) {
            out.status = status_of(static_cast<LSTATUS>(GetLastError()));
            return out;
        }
        struct Closer {
            HANDLE h;
            ~Closer() { FindClose(h); }
        } closer{h};
        for (;;) {
            const wchar_t* n = fd.cFileName;
            const bool dots = n[0] == L'.' && (n[1] == L'\0' || (n[1] == L'.' && n[2] == L'\0'));
            const bool is_dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            const bool reparse = (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
            if (!dots && is_dir && !reparse) { // a link is never followed, so never listed
                if (out.names.size() >= cap) {
                    out.truncated = true;
                    break;
                }
                out.names.push_back(yuzu::win::from_wide(n));
            }
            if (!FindNextFileW(h, &fd)) {
                if (GetLastError() != ERROR_NO_MORE_FILES) out.enum_failed = true;
                break;
            }
        }
        return out;
    }

    [[nodiscard]] FileRead read_file(std::string_view path, std::size_t cap) const {
        FileRead out;
        auto r = yuzu::win::read_file_bounded(yuzu::win::to_wide(path), cap);
        switch (r.status) {
        case yuzu::win::BoundedReadStatus::ok:
            out.bytes = std::move(r.bytes);
            break;
        case yuzu::win::BoundedReadStatus::absent: out.status = OpStatus::absent; break;
        case yuzu::win::BoundedReadStatus::denied: out.status = OpStatus::denied; break;
        default: out.status = OpStatus::error; break;
        }
        return out;
    }

private:
    [[nodiscard]] static OpStatus status_of(LSTATUS rc) noexcept {
        if (rc == ERROR_FILE_NOT_FOUND || rc == ERROR_PATH_NOT_FOUND) return OpStatus::absent;
        if (rc == ERROR_ACCESS_DENIED) return OpStatus::denied;
        return OpStatus::error;
    }
    [[nodiscard]] std::wstring key_path(std::string_view store_key) const {
        return appx_base_ + L"\\" + yuzu::win::to_wide(store_key);
    }

    HKEY root_ = HKEY_LOCAL_MACHINE;
    std::wstring appx_base_ =
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Appx\\AppxAllUserStore";
};

#endif // _WIN32

} // namespace yuzu::pkg_inventory::win
