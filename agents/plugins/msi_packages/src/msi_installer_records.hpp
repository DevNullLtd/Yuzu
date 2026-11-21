/**
 * msi_installer_records.hpp -- pure core of msi_packages.installer_records (SAM-46).
 *
 * Reads, per machine-context product, what Windows Installer itself recorded: the
 * `InstallProperties` values under
 *   HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\<packed>
 * and the Property table of the package cached under `<windir>\Installer`, plus the
 * UpgradeCode registry map list_inventory serves its sixth token from. Nothing is
 * executed: no product is opened, repaired, installed or configured, and the Installer
 * API that could do any of that is never called (a lexical case in
 * tests/unit/test_msi_installer_records.cpp pins it).
 *
 * No Windows headers. The OS boundary is injected as callables, so every decision here
 * (the packed-GUID codec, the LocalPackage path gate, the caps, the row-level reasons,
 * the privacy rule, the upgrade-code map, the row grammar) is unit-tested on every OS.
 * The Windows shell (registry reads with Reg*W, the held no-reparse handle, the call
 * into agent-core's bounded database read) is in msi_packages_plugin.cpp and
 * agents/core/src/msi_database_read.cpp.
 *
 * Wire grammar. The status row always leads (yuzu::shared::format_status_row):
 *
 *   status|installer_records|<supported|constrained|unsupported>|<tokens or ->
 *   rec|<product_code>|<name>|<version>|<publisher>|<install_date>|<install_location>
 *      |<install_source>|<local_package>|<upgrade_code>|<db_product_code>|<db_version>
 *      |<db_manufacturer>|<db_name>|<reason or ->                    (one per product)
 *
 * Fields the OS did not give are EMPTY, never `-` (only the reason is `-` when there is
 * none). The first five columns after the code are registry values; the last five before
 * the reason are the cached database's Property rows (ProductCode, UpgradeCode,
 * ProductVersion, Manufacturer, ProductName), the upgrade_code column being the
 * database's. A row-level problem (a missing, refused or corrupt package) is the row's
 * reason and never constrains the status; a failed registry read or a bound that cut the
 * read short is a status token and does (see the tokens below).
 */
#pragma once

#include <yuzu/agent/msi_database_read.hpp>

#include <constraint_accumulator.hpp>
#include <inventory_status_row.hpp>
#include <user_profile_model.hpp> // yuzu::profiles::iequals_ascii

#include "msi_packages_inventory.hpp" // strip_row_breakers

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yuzu::msi_packages::records {

inline constexpr std::string_view kAction = "installer_records";

// ── Bounds ──────────────────────────────────────────────────────────────────────

/// Records emitted at most. The 5,001st product stops the walk (token `row_cap`).
inline constexpr std::size_t kMaxRecords = 5000;
/// Subkeys visited at most under Products, GUID-shaped or not (a planted key stuffed with
/// junk names must not pin the walk); the same bound applies under UpgradeCodes.
inline constexpr std::size_t kMaxSubkeysVisited = 20000;
inline constexpr std::size_t kMaxUpgradeSubkeys = 20000;
/// Value names read under one UpgradeCodes subkey at most (a code is named by a handful
/// of products). The shell reads at most one past this so the builder can tell.
inline constexpr std::size_t kMaxUpgradeValueNames = 256;
/// Longest registry string (characters) read for a row field; a longer value is corrupt or
/// planted and fails the read instead of being truncated.
inline constexpr std::size_t kMaxValueChars = 4096;
/// Package reads in one dispatch: 5 s each (yuzu::agent::msi::kPackageDeadline), 45 s in all.
inline constexpr std::chrono::milliseconds kDispatchBudget{45000};

inline constexpr unsigned kErrorAccessDenied = 5;

// ── Status tokens (constrain the answer) ────────────────────────────────────────

inline constexpr std::string_view kTokenRowCap = "windows:installer_records:row_cap";
inline constexpr std::string_view kTokenDbDeadline = "windows:installer_records:msi_db:deadline";
inline constexpr std::string_view kTokenDbBusy = "windows:installer_records:msi_db:busy";
inline constexpr std::string_view kTokenAccessDenied = "windows:installer_records:access_denied";

[[nodiscard]] inline std::string enum_token(unsigned rc) {
    return "windows:installer_records:enum:" + std::to_string(rc);
}

/// A failed registry read (anything but an absent key or value). Access denied is its own
/// token: the agent's identity may be refused the S-1-5-18 UserData tree.
[[nodiscard]] inline std::string registry_failure_token(unsigned rc) {
    return rc == kErrorAccessDenied ? std::string{kTokenAccessDenied} : enum_token(rc);
}

[[nodiscard]] inline std::string upgrade_map_failure_token(unsigned rc) {
    return "windows:msi_upgrade_map:" + std::to_string(rc);
}

// ── Row-level reasons (never a status token) ────────────────────────────────────

inline constexpr std::string_view kReasonMissing = "package_missing";
inline constexpr std::string_view kReasonRefused = "package_path_refused";
inline constexpr std::string_view kReasonDeadline = "deadline_skipped";
inline constexpr std::string_view kReasonNoProperties = "no_install_properties";
inline constexpr std::string_view kReasonPropertiesUnreadable = "install_properties_unreadable";
inline constexpr std::string_view kReasonNoLocalPackage = "no_local_package";
inline constexpr std::string_view kReasonCodeMismatch = "product_code_mismatch";
inline constexpr std::string_view kWithheldUserPath = "withheld:user_path";

// ── Packed GUID codec ───────────────────────────────────────────────────────────
//
// Windows Installer registers a code as 32 hex digits, not as a braced GUID: the first
// three groups are reversed whole, and in the last two groups each pair of digits is
// swapped. {AC76BA86-7AD7-1033-7B44-AC0F074E4100} is 68AB67CA7DA73301B744CAF070E41400.

inline constexpr std::size_t kPackedGuidChars = 32;

namespace detail {

[[nodiscard]] inline bool is_hex(char c) noexcept {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

[[nodiscard]] inline std::string upper_hex(std::string_view s) {
    std::string out(s);
    for (char& c : out)
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return out;
}

[[nodiscard]] inline std::string reversed(std::string_view s) { return {s.rbegin(), s.rend()}; }

[[nodiscard]] inline std::string pair_swapped(std::string_view s) {
    std::string out(s);
    for (std::size_t i = 0; i + 1 < out.size(); i += 2)
        std::swap(out[i], out[i + 1]);
    return out;
}

} // namespace detail

/// Packed 32-digit form -> upper-case braced GUID. nullopt for a wrong length or a non-hex digit.
[[nodiscard]] inline std::optional<std::string> unpack_guid(std::string_view packed) {
    if (packed.size() != kPackedGuidChars || !std::all_of(packed.begin(), packed.end(), detail::is_hex))
        return std::nullopt;
    const std::string p = detail::upper_hex(packed);
    const std::string_view v{p};
    std::string out = "{";
    out += detail::reversed(v.substr(0, 8));
    out += '-';
    out += detail::reversed(v.substr(8, 4));
    out += '-';
    out += detail::reversed(v.substr(12, 4));
    out += '-';
    out += detail::pair_swapped(v.substr(16, 4));
    out += '-';
    out += detail::pair_swapped(v.substr(20, 12));
    out += '}';
    return out;
}

/// True for `{8-4-4-4-12}` hex, either case.
[[nodiscard]] inline bool is_braced_guid(std::string_view g) {
    if (g.size() != 38 || g.front() != '{' || g.back() != '}')
        return false;
    for (std::size_t i = 1; i + 1 < g.size(); ++i) {
        const bool dash = i == 9 || i == 14 || i == 19 || i == 24;
        if (dash ? g[i] != '-' : !detail::is_hex(g[i]))
            return false;
    }
    return true;
}

/// Braced GUID -> packed 32-digit upper-case form (the inverse of unpack_guid). nullopt
/// for anything that is not a braced GUID.
[[nodiscard]] inline std::optional<std::string> pack_guid(std::string_view braced) {
    if (!is_braced_guid(braced))
        return std::nullopt;
    const std::string g = detail::upper_hex(braced);
    const std::string_view v{g};
    std::string out;
    out += detail::reversed(v.substr(1, 8));
    out += detail::reversed(v.substr(10, 4));
    out += detail::reversed(v.substr(15, 4));
    out += detail::pair_swapped(v.substr(20, 4));
    out += detail::pair_swapped(v.substr(25, 12));
    return out;
}

/// A well-formed braced GUID in upper case; anything else unchanged. Product and upgrade
/// codes are compared and joined in this form (one machine registers its product code in
/// lower case, so a code is never trusted to arrive in the case the map spells it).
[[nodiscard]] inline std::string normalise_guid(std::string_view g) {
    return is_braced_guid(g) ? detail::upper_hex(g) : std::string(g);
}

// ── Path gate ───────────────────────────────────────────────────────────────────

/// True only for `<windows_dir>\Installer\<leaf>.msi`: the parent equals the Installer
/// directory under the system Windows directory, and the leaf is ONE plain name (no
/// separator, no stream colon, no wildcard or control character) ending `.msi`. Both
/// compares are ASCII case-insensitive and ordinal: the registry holds `C:\WINDOWS\...`
/// while an API may spell the directory `C:\Windows`, and a byte-exact compare would refuse
/// every row. Because the parent must equal a fixed absolute path and the leaf is one
/// component, a relative path, a `..` and a different directory cannot pass.
[[nodiscard]] inline bool package_path_allowed(std::string_view path, std::string_view windows_dir) {
    while (!windows_dir.empty() && windows_dir.back() == '\\')
        windows_dir.remove_suffix(1);
    // The Windows directory must itself be an absolute drive path.
    if (windows_dir.size() < 3 || windows_dir[1] != ':' || windows_dir[2] != '\\' ||
        !std::isalpha(static_cast<unsigned char>(windows_dir[0])))
        return false;
    const auto sep = path.rfind('\\');
    if (sep == std::string_view::npos)
        return false;
    const std::string_view parent = path.substr(0, sep);
    const std::string_view leaf = path.substr(sep + 1);
    constexpr std::string_view kInstaller = "\\Installer";
    if (parent.size() != windows_dir.size() + kInstaller.size() ||
        !yuzu::profiles::iequals_ascii(parent.substr(0, windows_dir.size()), windows_dir) ||
        !yuzu::profiles::iequals_ascii(parent.substr(windows_dir.size()), kInstaller))
        return false;
    constexpr std::string_view kExt = ".msi";
    if (leaf.size() <= kExt.size() ||
        !yuzu::profiles::iequals_ascii(leaf.substr(leaf.size() - kExt.size()), kExt))
        return false;
    return std::none_of(leaf.begin(), leaf.end(), [](char c) {
        return static_cast<unsigned char>(c) < 0x20 || c == '/' || c == ':' || c == '*' ||
               c == '?' || c == '"' || c == '<' || c == '>' || c == '|';
    });
}

// ── Privacy ─────────────────────────────────────────────────────────────────────

/// True when `path` is, or is under, one of `roots` (the user profiles directory and each
/// profile's folder). ASCII case-insensitive, either separator, a `\\?\` prefix ignored, and
/// a root only matches on a component boundary (`C:\UsersX` is not under `C:\Users`).
[[nodiscard]] inline bool path_under_any(std::string_view path,
                                         const std::vector<std::string>& roots) {
    const auto normal = [](std::string_view s) {
        if (s.starts_with("\\\\?\\"))
            s.remove_prefix(4);
        std::string out(s);
        for (char& c : out)
            c = c == '/' ? '\\' : static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return out;
    };
    const std::string p = normal(path);
    for (const auto& r : roots) {
        std::string root = normal(r);
        while (!root.empty() && root.back() == '\\')
            root.pop_back();
        if (root.empty())
            continue;
        if (p.size() >= root.size() && p.compare(0, root.size(), root) == 0 &&
            (p.size() == root.size() || p[root.size()] == '\\'))
            return true;
    }
    return false;
}

// ── Model ───────────────────────────────────────────────────────────────────────

/// The `InstallProperties` values the plugin reads (registry strings, UTF-8). An absent
/// value is empty.
struct InstallProps {
    std::string display_name;
    std::string display_version;
    std::string publisher;
    std::string install_location;
    std::string install_source;
    std::string local_package;
    std::string install_date;
};

enum class PackageState { ok, missing, path_refused, unreadable, deadline_skipped, not_recorded };

struct InstallerRecord {
    std::string product_code; ///< unpacked from the Products subkey name, upper case
    InstallProps props;
    yuzu::agent::msi::PropertyTable db; ///< the cached package's Property rows (empty unless ok)
    PackageState state = PackageState::not_recorded;
    std::string reason; ///< the row-level reason, empty when there is none
};

enum class OpenStatus { ok, absent, refused };

struct Context {
    std::string windows_dir;                 ///< GetSystemWindowsDirectoryW, e.g. `C:\WINDOWS`
    std::vector<std::string> profile_roots;  ///< the profiles directory and each profile folder
};

struct RecordSet {
    std::vector<InstallerRecord> records;
    yuzu::shared::ConstraintAccumulator constraints;
    std::size_t non_guid_subkeys = 0; ///< Products subkeys whose name is not a packed GUID (skipped)
};

[[nodiscard]] inline std::string unreadable_reason(const yuzu::agent::msi::Outcome& o) {
    using Kind = yuzu::agent::msi::Outcome::Kind;
    switch (o.kind) {
    case Kind::ApiUnavailable:
        return "package_unreadable:api_unavailable";
    case Kind::Exception:
        return "package_unreadable:exception";
    case Kind::Ok:
    case Kind::OpenFailed:
    case Kind::ViewFailed:
    case Kind::ReadFailed:
        break;
    }
    return "package_unreadable:" + std::to_string(o.rc);
}

/// Walks the machine Products keys and builds one record per product.
///
///   enumerate(on_key)             calls on_key(std::string packed_name) -> bool (false = stop)
///                                 per subkey of the Products key, and returns nullopt when the
///                                 walk ended (an absent key is an empty walk) or a failure token.
///   read_properties(packed_name)  -> std::expected<std::optional<InstallProps>, std::string>:
///                                 nullopt when the product has no InstallProperties key, a
///                                 failure token when the read FAILED (never an absent one).
///   open_package(path_utf8)       -> an object with `.status` (OpenStatus) that holds the file
///                                 open (no reparse point followed) until it is destroyed, which
///                                 happens after the database read below.
///   read_database(path, deadline) -> yuzu::agent::msi::ReadResult.
///
/// A missing, refused or corrupt package is that row's reason and nothing more. The first
/// TimedOut, Busy or ceiling-rejected read, or an exhausted dispatch budget, stops further
/// opens: that row and every later one is `deadline_skipped`, and the status says why.
template <class Enumerate, class ReadProperties, class OpenPackage, class ReadDatabase>
RecordSet collect_records(const Context& ctx, Enumerate&& enumerate, ReadProperties&& read_properties,
                          OpenPackage&& open_package, ReadDatabase&& read_database) {
    using yuzu::agent::msi::Outcome;
    using yuzu::agent::msi::ReadStatus;

    RecordSet set;
    bool reads_stopped = false;
    std::chrono::milliseconds used{0};
    std::size_t visited = 0;

    const auto privacy = [&](std::string v) {
        return path_under_any(v, ctx.profile_roots) ? std::string{kWithheldUserPath} : v;
    };

    const auto fill_package = [&](InstallerRecord& r) {
        if (r.props.local_package.empty()) {
            r.reason = std::string{kReasonNoLocalPackage};
            return;
        }
        if (!package_path_allowed(r.props.local_package, ctx.windows_dir)) {
            r.state = PackageState::path_refused;
            r.reason = std::string{kReasonRefused};
            return;
        }
        if (reads_stopped) {
            r.state = PackageState::deadline_skipped;
            r.reason = std::string{kReasonDeadline};
            return;
        }
        auto opened = open_package(r.props.local_package);
        if (opened.status == OpenStatus::absent) {
            r.state = PackageState::missing;
            r.reason = std::string{kReasonMissing};
            return;
        }
        if (opened.status != OpenStatus::ok) {
            r.state = PackageState::path_refused;
            r.reason = std::string{kReasonRefused};
            return;
        }
        const auto remaining = kDispatchBudget - used;
        if (remaining <= std::chrono::milliseconds{0}) {
            reads_stopped = true;
            set.constraints.add_failure(kTokenDbDeadline);
            r.state = PackageState::deadline_skipped;
            r.reason = std::string{kReasonDeadline};
            return;
        }
        const yuzu::agent::msi::ReadResult res =
            read_database(r.props.local_package, (std::min)(yuzu::agent::msi::kPackageDeadline, remaining));
        used += res.elapsed;
        if (res.status != ReadStatus::Completed) {
            reads_stopped = true;
            set.constraints.add_failure(res.status == ReadStatus::TimedOut ? kTokenDbDeadline
                                                                           : kTokenDbBusy);
            r.state = PackageState::deadline_skipped;
            r.reason = std::string{kReasonDeadline};
            return;
        }
        if (res.outcome.kind != Outcome::Kind::Ok) {
            r.state = PackageState::unreadable;
            r.reason = unreadable_reason(res.outcome);
            return;
        }
        r.state = PackageState::ok;
        r.db = res.outcome.props;
        r.db.product_code = normalise_guid(r.db.product_code);
        r.db.upgrade_code = normalise_guid(r.db.upgrade_code);
        if (!r.db.product_code.empty() &&
            !yuzu::profiles::iequals_ascii(r.db.product_code, r.product_code))
            r.reason = std::string{kReasonCodeMismatch};
    };

    const auto on_key = [&](std::string packed) -> bool {
        if (++visited > kMaxSubkeysVisited) {
            set.constraints.add_failure(kTokenRowCap);
            return false;
        }
        const auto code = unpack_guid(packed);
        if (!code) {
            ++set.non_guid_subkeys;
            return true;
        }
        if (set.records.size() >= kMaxRecords) {
            set.constraints.add_failure(kTokenRowCap);
            return false;
        }
        InstallerRecord r;
        r.product_code = *code;
        auto props = read_properties(packed);
        if (!props) {
            set.constraints.add_failure(props.error());
            r.reason = std::string{kReasonPropertiesUnreadable};
        } else if (!*props) {
            r.reason = std::string{kReasonNoProperties};
        } else {
            r.props = std::move(**props);
            r.props.install_location = privacy(std::move(r.props.install_location));
            r.props.install_source = privacy(std::move(r.props.install_source));
            fill_package(r); // reads local_package before it is withheld below
            r.props.local_package = privacy(std::move(r.props.local_package));
        }
        set.records.push_back(std::move(r));
        return true;
    };

    if (auto failure = enumerate(on_key))
        set.constraints.add_failure(*failure);
    return set;
}

/// Status row first (constrained iff a token was recorded), then one `rec` row per product.
[[nodiscard]] inline std::vector<std::string> render(const RecordSet& set) {
    std::vector<std::string> rows;
    rows.reserve(set.records.size() + 1);
    rows.push_back(set.constraints.any_failure()
                       ? yuzu::shared::format_status_row(kAction, yuzu::shared::StatusLevel::constrained,
                                                         set.constraints.reason())
                       : yuzu::shared::format_status_row(kAction, yuzu::shared::StatusLevel::supported, {}));
    for (const auto& r : set.records) {
        std::string row = "rec";
        const auto add = [&row](std::string_view field) {
            row += '|';
            row += yuzu::msi_packages::inventory::strip_row_breakers(field);
        };
        add(r.product_code);
        add(r.props.display_name);
        add(r.props.display_version);
        add(r.props.publisher);
        add(r.props.install_date);
        add(r.props.install_location);
        add(r.props.install_source);
        add(r.props.local_package);
        add(r.db.upgrade_code);
        add(r.db.product_code);
        add(r.db.product_version);
        add(r.db.manufacturer);
        add(r.db.product_name);
        row += '|';
        row += r.reason.empty() ? std::string{"-"} : yuzu::msi_packages::inventory::strip_row_breakers(r.reason);
        rows.push_back(std::move(row));
    }
    return rows;
}

[[nodiscard]] inline std::string unsupported_status_row(std::string_view token) {
    return yuzu::shared::format_status_row(kAction, yuzu::shared::StatusLevel::unsupported, token);
}

// ── Upgrade-code map (list_inventory's sixth token) ─────────────────────────────
//
// HKLM\SOFTWARE\Classes\Installer\UpgradeCodes: each subkey is a packed UPGRADE code and
// its value NAMES are the packed codes of the products it covers. Read once per dispatch
// from the registry alone (no file is opened, no worker is started), so the token for an
// installed set is the same every day: the server hashes it into instance_key, and a token
// that came and went with a timing budget would churn the rows.

struct UpgradeMap {
    struct Entry {
        std::string upgrade_code;
        bool ambiguous = false;
    };
    std::unordered_map<std::string, Entry> by_product; ///< upper-case braced product code
    std::size_t ambiguous = 0;  ///< products named under more than one upgrade code
    std::size_t bad_names = 0;  ///< subkey or value names that are not packed GUIDs (skipped)
    bool over_cap = false;      ///< too many subkeys or value names: every token is empty
    std::optional<std::string> failure; ///< a read fault (anything but an absent key)

    /// The upgrade code of `product_code`; empty when no upgrade code names it, more than
    /// one does, or the map is over its cap. A read fault is the failure token, so the
    /// roster is constrained rather than carrying a token a fault emptied.
    [[nodiscard]] std::expected<std::string, std::string> resolve(std::string_view product_code) const {
        if (failure)
            return std::unexpected(*failure);
        const auto it = by_product.find(normalise_guid(product_code));
        if (it == by_product.end() || it->second.ambiguous)
            return std::string{};
        return it->second.upgrade_code;
    }
};

/// enumerate(on_upgrade) calls on_upgrade(std::string packed_upgrade_code,
/// std::vector<std::string> packed_product_codes) -> bool (false = stop) per subkey, reading
/// at most kMaxUpgradeValueNames + 1 value names of each, and returns nullopt when the walk
/// ended (an absent key is an empty walk) or a failure token.
template <class Enumerate>
UpgradeMap build_upgrade_map(Enumerate&& enumerate) {
    UpgradeMap m;
    std::size_t subkeys = 0;
    const auto on_upgrade = [&](std::string packed_upgrade, std::vector<std::string> names) -> bool {
        if (++subkeys > kMaxUpgradeSubkeys || names.size() > kMaxUpgradeValueNames) {
            m.over_cap = true;
            return false;
        }
        const auto upgrade = unpack_guid(packed_upgrade);
        if (!upgrade) {
            ++m.bad_names;
            return true;
        }
        for (const auto& n : names) {
            const auto product = unpack_guid(n);
            if (!product) {
                ++m.bad_names;
                continue;
            }
            const auto [it, inserted] = m.by_product.try_emplace(*product, UpgradeMap::Entry{*upgrade, false});
            if (!inserted && it->second.upgrade_code != *upgrade)
                it->second.ambiguous = true;
        }
        return true;
    };
    m.failure = enumerate(on_upgrade);
    if (m.over_cap || m.failure) {
        m.by_product.clear(); // every token empty (over cap) or the roster constrained (fault)
    } else {
        for (const auto& [code, e] : m.by_product)
            m.ambiguous += e.ambiguous ? 1 : 0;
    }
    return m;
}

} // namespace yuzu::msi_packages::records
