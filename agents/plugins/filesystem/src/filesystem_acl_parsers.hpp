#pragma once

// filesystem_acl_parsers.hpp -- pure ACL decoders/formatters for the
// filesystem plugin's get_acl action.
//
// Portable and header-only: only the standard library and <yuzu/string_utils.hpp>, no OS
// headers, so every host compiles and unit-tests all three legs. The OS shells
// (getxattr / acl_get_file / GetAce) feed these functions raw bytes or text.
//
// Every leg emits ONE cross-OS row shape:
//
//     ace|<type>|<principal>|<perms>|<flags>      (`-` = empty principal/flags; perms is a
//                                                  hex access mask on Windows, `-` for an
//                                                  undecoded Windows type)
//
//   * Linux   <type> = user|group|mask|other; <flags> = `default` for entries
//             of the directory default ACL, else `-`.
//   * macOS   <type> = allow|deny; <flags> = inheritance flags.
//   * Windows <type> = allow|deny|allow_object|...|other; <flags> = ACE flags.
//
// Row-field escaping (row_field below): CR/LF fold to a space, a TRAILING
// backslash folds to '/', pipes are escaped. safe_output_field() is NOT used:
// it folds every backslash and would rewrite `BUILTIN\Users`. Interior
// backslashes survive because the server decoder (result_parsing.hpp) treats a
// backslash not followed by a pipe as literal data; only a trailing one would
// glue onto the field separator as `\|`.

#include <yuzu/string_utils.hpp>

#include <cstddef>
#include <cstdint>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::filesystem::acl {

inline std::string row_field(std::string_view value) {
    std::string out;
    out.reserve(value.size());
    for (char ch : value)
        out += (ch == '\r' || ch == '\n') ? ' ' : ch;
    if (!out.empty() && out.back() == '\\')
        out.back() = '/';
    return yuzu::util::escape_pipes(out);
}

namespace detail {
inline std::string join_or_dash(const std::vector<std::string>& v) {
    if (v.empty())
        return "-";
    std::string out;
    for (const auto& s : v) {
        if (!out.empty())
            out += ',';
        out += s;
    }
    return out;
}
}  // namespace detail

// ── Linux: system.posix_acl_access / system.posix_acl_default xattr value ───

inline constexpr std::uint32_t kPosixAclVersion = 0x00000002;
inline constexpr std::uint32_t kPosixAclUndefinedId = 0xFFFFFFFF;
inline constexpr std::uint16_t kAclUserObj = 0x01, kAclUser = 0x02, kAclGroupObj = 0x04,
                               kAclGroup = 0x08, kAclMask = 0x10, kAclOther = 0x20;

struct PosixAclEntry {
    std::uint16_t tag;
    std::uint16_t perm;
    std::uint32_t id;
};

namespace detail {
template <typename T> T le(std::string_view b, std::size_t off) {
    T v = 0;
    for (std::size_t i = 0; i < sizeof(T); ++i)
        v |= static_cast<T>(static_cast<T>(static_cast<unsigned char>(b[off + i])) << (8 * i));
    return v;
}
}  // namespace detail

/// nullopt on size < 4, a version other than 2, no entries at all, an unknown tag, or trailing
/// bytes that do not form a whole 8-byte entry -- never a partial vector. The kernel only
/// writes the six known tags; anything else means the bytes are not kernel-generated (a FUSE or
/// 9p filesystem without `posix_acl`) and must not render as a genuine entry.
inline std::optional<std::vector<PosixAclEntry>> decode_posix_acl_xattr(std::string_view bytes) {
    if (bytes.size() < 12 || (bytes.size() - 4) % 8 != 0 ||
        detail::le<std::uint32_t>(bytes, 0) != kPosixAclVersion)
        return std::nullopt;
    std::vector<PosixAclEntry> out;
    for (std::size_t off = 4; off < bytes.size(); off += 8) {
        const auto tag = detail::le<std::uint16_t>(bytes, off);
        if (tag != kAclUserObj && tag != kAclUser && tag != kAclGroupObj && tag != kAclGroup &&
            tag != kAclMask && tag != kAclOther)
            return std::nullopt;
        out.push_back({tag, detail::le<std::uint16_t>(bytes, off + 2),
                       detail::le<std::uint32_t>(bytes, off + 4)});
    }
    return out;
}

/// `qualifier_name` is resolved by the caller (name, or the numeric id as
/// text); the parser never does NSS. Ignored for tags without a qualifier.
inline std::string format_posix_ace(const PosixAclEntry& e, std::string_view qualifier_name,
                                    bool is_default) {
    std::string_view type = "other";
    bool qualified = false;
    switch (e.tag) {
    case kAclUserObj: type = "user"; break;
    case kAclUser: type = "user"; qualified = true; break;
    case kAclGroupObj: type = "group"; break;
    case kAclGroup: type = "group"; qualified = true; break;
    case kAclMask: type = "mask"; break;
    case kAclOther: type = "other"; break;
    default: break;
    }
    std::string perms = {(e.perm & 4) ? 'r' : '-', (e.perm & 2) ? 'w' : '-', (e.perm & 1) ? 'x' : '-'};
    std::string principal = "-";
    if (qualified)
        principal = qualifier_name.empty() ? std::to_string(e.id) : row_field(qualifier_name);
    return std::format("ace|{}|{}|{}|{}", type, principal, perms, is_default ? "default" : "-");
}

// ── macOS: libSystem acl_to_text() ──────────────────────────────────────────

struct MacosAclEntry {
    std::string kind;  // user|group
    std::string uuid;
    std::string name;  // empty when the principal is unresolved
    std::string id;    // empty when the principal is unresolved
    bool allow = true;
    std::vector<std::string> flags;
    std::vector<std::string> perms;
};

struct MacosAcl {
    std::vector<std::string> acl_flags;
    std::vector<MacosAclEntry> entries;
};

namespace detail {
inline std::vector<std::string> split(std::string_view s, char sep) {
    std::vector<std::string> out;
    std::size_t start = 0;
    while (true) {
        auto p = s.find(sep, start);
        if (p == std::string_view::npos) {
            out.emplace_back(s.substr(start));
            return out;
        }
        out.emplace_back(s.substr(start, p - start));
        start = p + 1;
    }
}
inline std::vector<std::string> split_nonempty(std::string_view s, char sep) {
    auto v = split(s, sep);
    std::erase_if(v, [](const std::string& x) { return x.empty(); });
    return v;
}
}  // namespace detail

/// Grammar: `!#acl 1[ <acl-flag>,...]` then one line per entry
/// `<kind>:<uuid>:<name>:<id>:<allow|deny>[,<flag>...]:<perm>[,<perm>...]`.
/// An unresolved principal prints `user:<uuid>:::allow,...:perms`.
/// nullopt when the header is missing or any entry is malformed.
inline std::optional<MacosAcl> parse_acl_to_text(std::string_view text) {
    auto lines = detail::split(text, '\n');
    constexpr std::string_view kHeader = "!#acl 1";
    if (lines.empty() || lines[0].compare(0, kHeader.size(), kHeader) != 0)
        return std::nullopt;
    MacosAcl acl;
    if (!lines[0].empty() && lines[0].back() == '\r')
        lines[0].pop_back();
    std::string_view hdr_rest = std::string_view{lines[0]}.substr(kHeader.size());
    if (!hdr_rest.empty() && hdr_rest.front() != ' ')
        return std::nullopt;
    acl.acl_flags = detail::split_nonempty(hdr_rest.substr(hdr_rest.empty() ? 0 : 1), ',');
    for (std::size_t i = 1; i < lines.size(); ++i) {
        auto& line = lines[i];
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty())
            continue;
        // The name may itself contain ':', so anchor on the first two and last three fields.
        auto f = detail::split(line, ':');
        const std::size_t n = f.size();
        const auto is_verdict = [](const std::string& field) {
            const auto first = field.substr(0, field.find(','));
            return first == "allow" || first == "deny";
        };
        // Normal layout: ...:<id>:<verdict>:<perms>. An ACE with an empty permission set (written
        // by acl_set_file, e.g. by a sync tool) prints with no perms field at all.
        std::size_t verdict_at;
        if (n >= 6 && is_verdict(f[n - 2]))
            verdict_at = n - 2;
        else if (n >= 5 && is_verdict(f[n - 1]))
            verdict_at = n - 1;
        else
            return std::nullopt;
        MacosAclEntry e;
        e.kind = f[0];
        e.uuid = f[1];
        for (std::size_t k = 2; k + 1 < verdict_at; ++k)
            e.name += (k > 2 ? ":" : "") + f[k];
        e.id = f[verdict_at - 1];
        auto verdict = detail::split(f[verdict_at], ',');
        e.allow = verdict[0] == "allow";
        e.flags.assign(verdict.begin() + 1, verdict.end());
        if (verdict_at + 1 < n)
            e.perms = detail::split_nonempty(f[verdict_at + 1], ',');
        acl.entries.push_back(std::move(e));
    }
    return acl;
}

/// Principal: name -> `<kind>:<name>`; else id -> `<kind>:#<id>`; else
/// `<kind>:<UUID>` so distinct unresolved principals stay distinct.
inline std::string format_macos_ace(const MacosAclEntry& e) {
    std::string principal = e.kind + ':';
    if (!e.name.empty())
        principal += e.name;
    else if (!e.id.empty())
        principal += '#' + e.id;
    else
        principal += e.uuid;
    return std::format("ace|{}|{}|{}|{}", e.allow ? "allow" : "deny", row_field(principal),
                       row_field(detail::join_or_dash(e.perms)),
                       row_field(detail::join_or_dash(e.flags)));
}

// ── Windows: plain-integer ACE formatting (no Windows headers) ──────────────

inline std::string_view win_ace_type_name(unsigned char t) {
    switch (t) {
    case 0x0: return "allow";
    case 0x1: return "deny";
    case 0x5: return "allow_object";
    case 0x6: return "deny_object";
    case 0x9: return "allow_conditional";
    case 0xA: return "deny_conditional";
    default: return "other";
    }
}

inline std::string win_ace_flags(unsigned char f) {
    std::vector<std::string> v;
    if (f & 0x01) v.emplace_back("object_inherit");
    if (f & 0x02) v.emplace_back("container_inherit");
    if (f & 0x04) v.emplace_back("no_propagate");
    if (f & 0x08) v.emplace_back("inherit_only");
    if (f & 0x10) v.emplace_back("inherited");
    return detail::join_or_dash(v);
}

inline std::string win_control_flags(unsigned control) {
    std::vector<std::string> v;
    if (control & 0x1000) v.emplace_back("protected");       // SE_DACL_PROTECTED
    if (control & 0x0400) v.emplace_back("auto_inherited");  // SE_DACL_AUTO_INHERITED
    return detail::join_or_dash(v);
}

/// Offset of the SID inside an object ACE: ACE_HEADER 4 + Mask 4 + Flags 4,
/// plus a 16-byte GUID per ACE_OBJECT_TYPE_PRESENT (0x1) /
/// ACE_INHERITED_OBJECT_TYPE_PRESENT (0x2). nullopt when the ACE cannot hold
/// the 8-byte minimum SID (revision, subauth count, 6-byte authority).
inline std::optional<std::size_t> win_object_ace_sid_offset(std::uint32_t object_flags,
                                                            std::uint16_t ace_size) {
    std::size_t off = 12;
    if (object_flags & 0x1) off += 16;
    if (object_flags & 0x2) off += 16;
    if (ace_size < off + 8)
        return std::nullopt;
    return off;
}

/// True when `ace` (exactly AceSize bytes) holds a well-formed SID at `sid_off`: revision 1, at
/// most 15 sub-authorities, and the whole SID inside the ACE. Checked before the SID is handed to
/// any Windows API, which would otherwise read past a short ACE.
inline bool win_ace_sid_ok(std::string_view ace, std::size_t sid_off) {
    if (ace.size() < sid_off + 8 || static_cast<unsigned char>(ace[sid_off]) != 1)
        return false;
    const auto count = static_cast<unsigned char>(ace[sid_off + 1]);
    return count <= 15 && ace.size() >= sid_off + 8 + 4 * static_cast<std::size_t>(count);
}

/// `mask` is nullopt for a type this plugin does not decode: the row then carries `-` instead of
/// a zero mask that would read as "no rights". An empty principal is `-` too.
inline std::string format_win_ace(unsigned char type, unsigned char flags, std::string_view account,
                                  std::optional<std::uint32_t> mask) {
    return std::format("ace|{}|{}|{}|{}", win_ace_type_name(type),
                       account.empty() ? std::string{"-"} : row_field(account),
                       mask ? std::format("0x{:08x}", *mask) : std::string{"-"},
                       win_ace_flags(flags));
}

inline std::string format_control_row(unsigned control) {
    return "control|" + win_control_flags(control);
}

}  // namespace yuzu::filesystem::acl
