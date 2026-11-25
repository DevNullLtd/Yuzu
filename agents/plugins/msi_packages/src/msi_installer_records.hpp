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
 * none). The seven columns after the code (name through local_package) are registry
 * values; the five before the reason are the cached database's Property rows
 * (UpgradeCode, ProductCode, ProductVersion, Manufacturer, ProductName), the upgrade_code
 * column being the database's. A row-level problem (a missing, refused or corrupt package) is the row's
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
/// Value names read under one UpgradeCodes subkey at most (a code is named by a handful
/// of products). The shell reads at most one past this so the builder can tell.
inline constexpr std::size_t kMaxUpgradeValueNames = 256;
/// Longest registry string (characters) read for a row field; a longer value is corrupt or
/// planted and fails the read instead of being truncated.
inline constexpr std::size_t kMaxValueChars = 4096;
/// Value names read across the WHOLE UpgradeCodes tree at most (one name per product an
/// upgrade code covers). The subkey and per-subkey bounds alone allow 20,000 x 256 = about
/// 5.1 million names, and each becomes a map entry, from a planted tree; this holds the total
/// to one name per visited subkey on average. A real machine registers each of its products
/// under one upgrade code, so the total is about its product count: hundreds, and 5,000
/// products (kMaxRecords) is a quarter of the cap. Over it the map is over_cap, which is a
/// failure token (kTokenUpgradeMapOverCap): the roster is constrained.
inline constexpr std::size_t kMaxUpgradeNames = kMaxSubkeysVisited;
/// Text bytes the records may hold in all (every string field of every record, as read). The
/// per-field bounds alone allow 5,000 rows x 12 fields x 4,096 characters = about 246 million
/// characters, up to three UTF-8 bytes each, from planted values. This holds the total to one
/// full-length value (kMaxValueChars) per row on average: 5,000 x 4,096 = 20,480,000 bytes. A
/// real row (a code, a name, a version, a publisher, a date, three paths and the cached
/// package's five Property values) is about half a KiB, so 5,000 real products take about
/// 2.5 MB (an eighth of the cap) and a few hundred take well under 0.25 MB. Over it the walk
/// stops with the `row_cap` token and the records read so far are kept.
inline constexpr std::size_t kMaxRecordBytes = kMaxRecords * kMaxValueChars;
/// Package reads in one dispatch: 5 s each (yuzu::agent::msi::kPackageDeadline), 45 s in all.
inline constexpr std::chrono::milliseconds kDispatchBudget{45000};

inline constexpr unsigned kErrorAccessDenied = 5;

// ── Status tokens (constrain the answer) ────────────────────────────────────────

inline constexpr std::string_view kTokenRowCap = "windows:installer_records:row_cap";
inline constexpr std::string_view kTokenDbDeadline = "windows:installer_records:msi_db:deadline";
inline constexpr std::string_view kTokenDbBusy = "windows:installer_records:msi_db:busy";
inline constexpr std::string_view kTokenAccessDenied = "windows:installer_records:access_denied";
/// The privacy gate withheld paths because the ProfileList read was incomplete.
inline constexpr std::string_view kTokenProfileListIncomplete =
    "windows:installer_records:profile_list_incomplete";
/// The UpgradeCodes walk was cut short by a bound: constrained like a failed read.
inline constexpr std::string_view kTokenUpgradeMapOverCap = "windows:msi_upgrade_map:over_cap";

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
/// The user-profile list could not be read in full, so no path can be shown to be outside a
/// profile: every path-bearing field is withheld under this value (fail closed).
inline constexpr std::string_view kWithheldProfileList = "withheld:profile_list_incomplete";
/// A path off the path allow-list (see THE RULE under Privacy: not a plain drive-absolute or
/// UNC path of plain segments) is withheld: it cannot be compared with a profile root.
inline constexpr std::string_view kWithheldPathUnverifiable = "withheld:path_unverifiable";

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

/// True when the leaf's base name is a Windows reserved device name: CON, PRN, AUX, NUL,
/// COM1-9 or LPT1-9, in any case. Windows resolves such a name with ANY extension to the
/// device, not to a file (`CON.msi` is the console), and ignores spaces before the dot, so
/// the base is what precedes the first '.', trailing spaces trimmed.
[[nodiscard]] inline bool is_reserved_device_name(std::string_view leaf) {
    std::string_view base = leaf.substr(0, leaf.find('.'));
    while (!base.empty() && base.back() == ' ')
        base.remove_suffix(1);
    using yuzu::profiles::iequals_ascii;
    for (const std::string_view device : {"CON", "PRN", "AUX", "NUL"})
        if (iequals_ascii(base, device))
            return true;
    return base.size() == 4 && base[3] >= '1' && base[3] <= '9' &&
           (iequals_ascii(base.substr(0, 3), "COM") || iequals_ascii(base.substr(0, 3), "LPT"));
}

// ── Path allow-list helpers (the privacy gate below) ──────────────────────────

/// ASCII-only case fold (A-Z); every other byte is returned unchanged. Locale independent.
[[nodiscard]] constexpr char ascii_fold(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

[[nodiscard]] constexpr bool is_alnum(char c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
}

/// One path segment (already folded, never `.` or `..`) is on the allow-list when it is
/// non-empty, does not start or end with a space or a dot (Win32 trims those, so such a
/// name is not the name it looks like), is not an 8.3 short name (`~` then a digit), and
/// holds only: letters, digits, a space inside the name, any non-ASCII byte (UTF-8 text),
/// and the punctuation  - _ . ( ) [ ] { } & + , ; = @ # ! ' $ ^ ~ . Everything else is out,
/// notably `:` (an NTFS stream or a drive), `%`, `*`, `?`, `"`, `<`, `>`, `|`, `\`, `/`,
/// a control character, NUL and DEL.
[[nodiscard]] inline bool segment_allowed(std::string_view seg) noexcept {
    if (seg.empty() || seg.front() == ' ' || seg.front() == '.' || seg.back() == ' ' ||
        seg.back() == '.')
        return false;
    for (std::size_t i = 0; i < seg.size(); ++i) {
        const char c = seg[i];
        const bool ok = is_alnum(c) || c == ' ' || static_cast<unsigned char>(c) >= 0x80 ||
                        std::string_view{"-_.()[]{}&+,;=@#!'$^~"}.find(c) != std::string_view::npos;
        if (!ok)
            return false;
        if (c == '~' && i + 1 < seg.size() && seg[i + 1] >= '0' && seg[i + 1] <= '9')
            return false;
    }
    return true;
}

/// A UNC server is kept only as a plain DNS-style name: dot-separated labels of letters,
/// digits and inner hyphens; no label purely numeric or starting `0x` (any IPv4 spelling,
/// `0`, `127.1`); no label `localhost` or a name starting `localhost`; no `ipv6-literal.net`
/// suffix. Anything else (`.`, `?`, an IPv6 literal, a trailing dot, `[::1]`) is out.
[[nodiscard]] inline bool unc_server_allowed(std::string_view server) noexcept {
    constexpr std::string_view kV6 = "ipv6-literal.net";
    if (server.empty() || server.back() == '.' || server.starts_with("localhost") ||
        (server.size() >= kV6.size() && server.substr(server.size() - kV6.size()) == kV6))
        return false;
    while (!server.empty()) {
        const auto dot = server.find('.');
        const std::string_view label = server.substr(0, dot);
        server = dot == std::string_view::npos ? std::string_view{} : server.substr(dot + 1);
        if (label.empty() || label == "localhost" || label.front() == '-' || label.back() == '-' ||
            label.starts_with("0x") ||
            std::all_of(label.begin(), label.end(), [](char c) { return c >= '0' && c <= '9'; }))
            return false;
        if (!std::all_of(label.begin(), label.end(),
                         [](char c) { return is_alnum(c) || c == '-'; }))
            return false;
    }
    return true;
}

/// A UNC share is kept only as a plain name: no `$` (so no `C$`, `ADMIN$`, `IPC$`, `print$`)
/// and the segment allow-list.
[[nodiscard]] inline bool unc_share_allowed(std::string_view share) noexcept {
    return share.find('$') == std::string_view::npos && segment_allowed(share);
}

/// One code point of a folded UTF-8 path: an ASCII byte, or `wide` for any non-ASCII code
/// point (a malformed byte counts as one).
struct Cp {
    char c = 0;
    bool wide = false;
};

[[nodiscard]] inline Cp take_cp(std::string_view s, std::size_t& i) noexcept {
    const auto b = static_cast<unsigned char>(s[i++]);
    if (b < 0x80)
        return {static_cast<char>(b), false};
    // only the continuation bytes the lead byte declares: a lone continuation byte or an
    // invalid lead is one code point by itself
    std::size_t extra = 0;
    if (b >= 0xF0 && b < 0xF8)
        extra = 3;
    else if (b >= 0xE0 && b < 0xF0)
        extra = 2;
    else if (b >= 0xC0 && b < 0xE0)
        extra = 1;
    while (extra != 0 && i < s.size() && (static_cast<unsigned char>(s[i]) & 0xC0) == 0x80) {
        ++i;
        --extra;
    }
    return {0, true};
}

/// ASCII code points compare exactly (already folded). A non-ASCII code point may be a case
/// variant of any ASCII letter (U+017F is `s`, U+0131 is `i`, U+212A is `k`) or of any other
/// non-ASCII code point, and the NTFS case table is not reproduced, so it possibly equals
/// either: the gate over-withholds, never the reverse. It still never equals a digit,
/// punctuation or the separator.
[[nodiscard]] constexpr bool cp_may_equal(Cp a, Cp b) noexcept {
    if (!a.wide && !b.wide)
        return a.c == b.c;
    const Cp other = a.wide ? b : a;
    return other.wide || (other.c >= 'a' && other.c <= 'z');
}

/// True when `root` is, code point by code point under cp_may_equal, a prefix of `p` that ends
/// on a segment boundary.
[[nodiscard]] inline bool key_under(std::string_view p, std::string_view root) noexcept {
    std::size_t i = 0;
    std::size_t j = 0;
    while (j < root.size()) {
        if (i >= p.size())
            return false;
        const Cp a = take_cp(p, i);
        const Cp b = take_cp(root, j);
        if (!cp_may_equal(a, b))
            return false;
    }
    return i == p.size() || p[i] == '\\';
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

/// A well-formed braced GUID in upper case; anything else unchanged. Product and upgrade
/// codes are compared and joined in this form (one machine registers its product code in
/// lower case, so a code is never trusted to arrive in the case the map spells it).
[[nodiscard]] inline std::string normalise_guid(std::string_view g) {
    return is_braced_guid(g) ? detail::upper_hex(g) : std::string(g);
}

// ── Path gate ───────────────────────────────────────────────────────────────────

/// True only for `<windows_dir>\Installer\<leaf>.msi`: the parent equals the Installer
/// directory under the system Windows directory, and the leaf is ONE plain name (no
/// separator, no stream colon, no wildcard or control character, not a reserved device
/// name such as `CON` or `COM1`) ending `.msi`. Both
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
        !yuzu::profiles::iequals_ascii(leaf.substr(leaf.size() - kExt.size()), kExt) ||
        detail::is_reserved_device_name(leaf))
        return false;
    return std::none_of(leaf.begin(), leaf.end(), [](char c) {
        return static_cast<unsigned char>(c) < 0x20 || c == '/' || c == ':' || c == '*' ||
               c == '?' || c == '"' || c == '<' || c == '>' || c == '|';
    });
}

// ── Privacy ─────────────────────────────────────────────────────────────────────
//
// THE RULE (an allow-list; everything else is withheld). A non-empty path is EMITTED only
// when, after normalisation, it is (1) a plain drive-absolute path (`X:\...`, X one ASCII
// letter) or a plain UNC path (`\\server\share\...`), (2) every segment is on the segment
// allow-list and the UNC server and share on theirs (detail::segment_allowed,
// unc_server_allowed, unc_share_allowed), and (3) it is not under a profile root. A path under
// a root is withheld as `withheld:user_path`; a path that fails (1) or (2) as
// `withheld:path_unverifiable`. A root must pass (1) and (2) as well, or the profile list is
// incomplete. Residual, still emitted because nothing here can see them: junctions, symbolic
// links, mount points, `subst` and mapped drives, a UNC path naming this machine by its own
// DNS name or its NetBIOS or short name, and a case variant that needs a multi-character fold
// (such as `ss` for U+00DF).

/// A path reduced to its comparable form. `comparable` is false when it is not on the
/// allow-list: it is then neither compared nor emitted.
struct NormalPath {
    std::string text; ///< folded, no `.`/`..`; meaningful only if comparable
    bool comparable = false;
    bool unc = false;
    /// What a root is matched on: the whole text for a drive path, and share plus rest (the
    /// server dropped) for a UNC path, so the root `\\fs\home\carol` also covers
    /// `\\fs.corp.example\home\carol\x`.
    [[nodiscard]] std::string_view key() const noexcept {
        std::string_view k = text;
        if (unc)
            k.remove_prefix(k.find('\\', 2));
        return k;
    }
};

/// Normalises a path as Win32 reads a plain path, and gives up (not comparable) on anything
/// the allow-list does not cover: `/` is read as `\`, ASCII is folded, repeated separators
/// collapse, `.` segments drop, `..` segments pop, and the drive (`c:`) or the UNC
/// `\\server\share` stays OUTSIDE the segment stack, so an excess `..` clamps at the root as
/// Win32 does. A `\\?\`, `\\.\` or `\??\` prefix, a rooted path with no drive, a
/// drive-relative one, a control character, a segment that is only dots or spaces (other than
/// exactly `.` and `..`) and every segment, server or share the allow-list rejects make it
/// not comparable. The first segment `Documents and Settings` (a junction) does too.
[[nodiscard]] inline NormalPath normalise_path(std::string_view s) {
    std::string in(s);
    for (char& c : in)
        c = c == '/' ? '\\' : detail::ascii_fold(c);
    if (std::any_of(in.begin(), in.end(),
                    [](char c) { return static_cast<unsigned char>(c) < 0x20 || c == 0x7f; }))
        return {};
    const bool unc = in.starts_with("\\\\");
    if (unc && (in.starts_with("\\\\?\\") || in.starts_with("\\\\.\\") ||
                in.starts_with("\\\\\\")))
        return {};
    if (in.starts_with("\\??\\") || (!unc && in.starts_with("\\")))
        return {};
    std::vector<std::string> segs;
    for (std::string_view rest = in; !rest.empty();) {
        const auto sep = rest.find('\\');
        if (sep != 0)
            segs.emplace_back(rest.substr(0, sep));
        rest = sep == std::string_view::npos ? std::string_view{} : rest.substr(sep + 1);
    }
    std::string prefix;
    std::size_t first = 0;
    if (unc) {
        if (segs.size() < 2 || !detail::unc_server_allowed(segs[0]) ||
            !detail::unc_share_allowed(segs[1]))
            return {};
        prefix = "\\\\" + segs[0] + "\\" + segs[1];
        first = 2;
    } else {
        // `x:` as its own first segment, followed by a separator: `c:` and `c:x` are
        // drive-relative
        if (segs.empty() || segs[0].size() != 2 || segs[0][1] != ':' || segs[0][0] < 'a' ||
            segs[0][0] > 'z' || in.size() < 3 || in[2] != '\\')
            return {};
        prefix = segs[0];
        first = 1;
    }
    std::vector<std::string> stack;
    for (std::size_t i = first; i < segs.size(); ++i) {
        if (segs[i] == ".")
            continue;
        if (segs[i] == "..") {
            if (!stack.empty())
                stack.pop_back(); // never pops the prefix: an excess `..` clamps at the root
            continue;
        }
        if (!detail::segment_allowed(segs[i]))
            return {};
        stack.push_back(segs[i]);
    }
    if (!unc && !stack.empty() && stack.front() == "documents and settings")
        return {};
    NormalPath out;
    out.text = std::move(prefix);
    for (const auto& seg : stack)
        out.text += "\\" + seg;
    out.comparable = true;
    out.unc = unc;
    return out;
}

enum class PathVerdict { keep, user_path, unverifiable };

/// The profile roots, normalised once. A root that is not comparable is skipped here (the
/// profile list is then incomplete: see count_unresolved_roots).
struct ProfileGate {
    std::vector<std::string> roots; ///< NormalPath::key() of each usable root
    explicit ProfileGate(const std::vector<std::string>& raw) {
        for (const auto& r : raw)
            if (const auto n = normalise_path(r); n.comparable)
                roots.emplace_back(n.key());
    }
};

/// The gate's decision for a non-empty path (see THE RULE above). A UNC root matches on its
/// share and path whatever the server's spelling (fail closed: the same share under a short
/// name, an FQDN or an alias is the same profile). A drive key starts `x:` and a UNC key
/// starts with a separator, so the two kinds can never match each other.
[[nodiscard]] inline PathVerdict classify_path(std::string_view path, const ProfileGate& gate) {
    const NormalPath p = normalise_path(path);
    if (!p.comparable)
        return PathVerdict::unverifiable;
    for (const auto& root : gate.roots)
        if (detail::key_under(p.key(), root))
            return PathVerdict::user_path;
    return PathVerdict::keep;
}

[[nodiscard]] inline PathVerdict classify_path(std::string_view path,
                                               const std::vector<std::string>& roots) {
    return classify_path(path, ProfileGate{roots});
}

inline constexpr long kErrorNoMoreItems = 259; ///< ERROR_NO_MORE_ITEMS (bound in the plugin)

/// How one ProfileList walk ended, as plain numbers (no Windows header): the codes and
/// counts of yuzu::win::ProfileListEnumeration. Defaults describe a clean, complete walk.
struct ProfileListFacts {
    long root_rc = 0;                      ///< opening ProfileList itself
    long last_rc = kErrorNoMoreItems;      ///< the RegEnumKeyExW code that ended the walk (0 = cap)
    long probe_rc = kErrorNoMoreItems;     ///< the extra enumeration run only at the cap
    bool truncated = false;                ///< the cap was reached and more subkeys exist
    std::size_t record_failures = 0;       ///< SID keys / ProfileImagePath values that failed
    std::size_t unreadable_paths = 0;      ///< ProfileImagePath exists but is unusable
    std::size_t unresolved_roots = 0;      ///< roots that are off the path allow-list or hold `%`
    std::size_t profiles_without_path = 0; ///< non-system profiles with no ProfileImagePath
    bool profiles_dir_failed = false;      ///< ProfilesDirectory could not be read
};

/// A root is usable only when it is on the path allow-list (a plain drive-absolute or UNC path
/// of plain segments, see normalise_path) and holds no `%` (an undefined variable stays in
/// place after expansion, and the expansion helper returns its input when the API fails).
/// Anything else can never match a path, so the list cannot be trusted to cover that profile.
[[nodiscard]] inline std::size_t count_unresolved_roots(const std::vector<std::string>& roots) {
    return static_cast<std::size_t>(std::count_if(roots.begin(), roots.end(), [](const auto& r) {
        return r.find('%') != std::string::npos || !normalise_path(r).comparable;
    }));
}

/// True only when every profile subkey was enumerated and read: the list is then a complete
/// set of profile folders. Any open or enumeration fault, the 512-profile cap with more behind
/// it, one profile whose key or path could not be read or is absent, or a root that is off the
/// path allow-list makes it incomplete, and the privacy gate then withholds every path.
[[nodiscard]] constexpr bool profile_list_complete(const ProfileListFacts& f) noexcept {
    if (f.root_rc != 0 || f.truncated || f.record_failures != 0 || f.unreadable_paths != 0 ||
        f.unresolved_roots != 0 || f.profiles_without_path != 0 || f.profiles_dir_failed)
        return false;
    if (f.last_rc == kErrorNoMoreItems)
        return true;
    return f.last_rc == 0 && f.probe_rc == kErrorNoMoreItems; // exactly the cap, nothing behind
}

/// The one decision the plugin shell makes: `roots` (the profiles directory and each profile
/// folder, as expanded, none dropped) and the walk's facts. The unresolved-root count is
/// derived here from the roots themselves.
[[nodiscard]] inline bool profile_roots_complete(const std::vector<std::string>& roots,
                                                 ProfileListFacts facts) {
    facts.unresolved_roots = count_unresolved_roots(roots);
    return profile_list_complete(facts);
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

struct InstallerRecord {
    std::string product_code; ///< unpacked from the Products subkey name, upper case
    InstallProps props;
    /// the cached package's Property rows (empty unless the package was read)
    yuzu::agent::msi::PropertyTable db;
    std::string reason; ///< the row-level reason, empty when there is none
};

/// Every string a record holds, in bytes: what kMaxRecordBytes bounds in aggregate.
[[nodiscard]] inline std::size_t record_bytes(const InstallerRecord& r) {
    return r.product_code.size() + r.props.display_name.size() + r.props.display_version.size() +
           r.props.publisher.size() + r.props.install_location.size() +
           r.props.install_source.size() + r.props.local_package.size() +
           r.props.install_date.size() + r.db.product_code.size() + r.db.upgrade_code.size() +
           r.db.product_version.size() + r.db.manufacturer.size() + r.db.product_name.size() +
           r.reason.size();
}

enum class OpenStatus { ok, absent, refused };

struct Context {
    std::string windows_dir;                 ///< GetSystemWindowsDirectoryW, e.g. `C:\WINDOWS`
    std::vector<std::string> profile_roots;  ///< the profiles directory and each profile folder
    /// False when the ProfileList read was incomplete (profile_list_complete): the privacy
    /// gate then withholds every path-bearing field instead of matching against the roots.
    bool profile_roots_complete = true;
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
/// opens: that row and every later one is `deadline_skipped`, and the status says why. More
/// than kMaxRecords records, or more than kMaxRecordBytes of text in all, ends the walk with
/// the `row_cap` token.
template <class Enumerate, class ReadProperties, class OpenPackage, class ReadDatabase>
RecordSet collect_records(const Context& ctx, Enumerate&& enumerate, ReadProperties&& read_properties,
                          OpenPackage&& open_package, ReadDatabase&& read_database) {
    using yuzu::agent::msi::Outcome;
    using yuzu::agent::msi::ReadStatus;

    RecordSet set;
    bool reads_stopped = false;
    std::chrono::milliseconds used{0};
    std::size_t visited = 0;
    std::size_t text_bytes = 0; // record_bytes() summed over the records kept

    // An incomplete profile list constrains the answer on its own, whether or not any field
    // turns out to carry a path: the gate then has no root list to compare against.
    if (!ctx.profile_roots_complete)
        set.constraints.add_failure(kTokenProfileListIncomplete);
    const ProfileGate gate{ctx.profile_roots};
    const auto privacy = [&](std::string v) {
        if (v.empty())
            return v;
        if (!ctx.profile_roots_complete) // fail closed: no usable root list
            return std::string{kWithheldProfileList};
        switch (classify_path(v, gate)) {
        case PathVerdict::unverifiable:
            return std::string{kWithheldPathUnverifiable};
        case PathVerdict::user_path:
            return std::string{kWithheldUserPath};
        case PathVerdict::keep:
            break;
        }
        return v;
    };

    const auto fill_package = [&](InstallerRecord& r) {
        if (r.props.local_package.empty()) {
            r.reason = std::string{kReasonNoLocalPackage};
            return;
        }
        if (!package_path_allowed(r.props.local_package, ctx.windows_dir)) {
            r.reason = std::string{kReasonRefused};
            return;
        }
        if (reads_stopped) {
            r.reason = std::string{kReasonDeadline};
            return;
        }
        auto opened = open_package(r.props.local_package);
        if (opened.status == OpenStatus::absent) {
            r.reason = std::string{kReasonMissing};
            return;
        }
        if (opened.status != OpenStatus::ok) {
            r.reason = std::string{kReasonRefused};
            return;
        }
        const auto remaining = kDispatchBudget - used;
        if (remaining <= std::chrono::milliseconds{0}) {
            reads_stopped = true;
            set.constraints.add_failure(kTokenDbDeadline);
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
            r.reason = std::string{kReasonDeadline};
            return;
        }
        if (res.outcome.kind != Outcome::Kind::Ok) {
            r.reason = unreadable_reason(res.outcome);
            return;
        }
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
        const std::size_t bytes = record_bytes(r);
        if (bytes > kMaxRecordBytes - text_bytes) { // aggregate cap: this row is not kept
            set.constraints.add_failure(kTokenRowCap);
            return false;
        }
        text_bytes += bytes;
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
    std::size_t bad_names = 0;  ///< subkey or value names that are not packed GUIDs (skipped)
    bool over_cap = false;      ///< too many subkeys or value names (per key or in all)
    /// A read fault (anything but an absent key) or the over-cap token: the roster is then
    /// constrained, never a clean one with every token emptied.
    std::optional<std::string> failure;

    /// The upgrade code of `product_code`; empty when no upgrade code names it, more than
    /// one does. A read fault or an over-cap map is the failure token, so the roster is
    /// constrained rather than carrying a token a fault or a bound emptied.
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
    std::size_t names_seen = 0;
    const auto on_upgrade = [&](std::string packed_upgrade, std::vector<std::string> names) -> bool {
        names_seen += names.size(); // at most kMaxUpgradeValueNames + 1 each, so no overflow
        if (++subkeys > kMaxSubkeysVisited || names.size() > kMaxUpgradeValueNames ||
            names_seen > kMaxUpgradeNames) {
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
    if (m.over_cap && !m.failure)
        m.failure = std::string{kTokenUpgradeMapOverCap};
    if (m.failure)
        m.by_product.clear(); // the roster is constrained: no row carries a partial token
    return m;
}

} // namespace yuzu::msi_packages::records
