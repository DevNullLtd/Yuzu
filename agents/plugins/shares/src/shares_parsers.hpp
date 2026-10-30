#pragma once

// shares_parsers.hpp -- pure parsers and row formatters for the shares plugin: what this
// host CONFIGURES to serve over SMB/NFS (the Windows leg reports LIVE shares through
// shares_legs.hpp's list_windows and shares only the row formatters). Header-only and
// portable so the unit tests run on every host; no file I/O, no subprocess, no OS header.
//
//   parse_exports       Linux exports(5) grammar (/etc/exports, /etc/exports.d/*.exports)
//   parse_bsd_exports   macOS exports(5) grammar as Apple's mountd reads /etc/exports
//   parse_smb_conf      Samba smb.conf: share sections, synonyms, `copy =` and [global]
//                       inheritance, plus detection of the parts this plugin does not read
//   parse_sharing_json  macOS `sharing -l -f json` share points (SMB)
//
// NAMES AND PATHS ONLY, NEVER ACLs. NFS client host lists are never emitted: a share carries
// `clients_<n>` and an `anonymous` flag only. Every parser charges a caller-owned
// yuzu::shared::RowByteBudget BEFORE materialising a share and stops at the first refusal,
// so allocation is bounded by the budget plus the input, independent of section count.
//
// The `status|list|...` row is NOT built here; shares_legs.hpp's report_list owns it.

#include <ini_parse.hpp>
#include <nlohmann/json.hpp>
#include <row_byte_budget.hpp>
#include <wire_utf8.hpp>
#include <yuzu/string_utils.hpp>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::shares {

enum class Proto { nfs, smb };
enum class Access { ro, rw, mixed, unknown };
enum class SourceState { read, absent, refused, failed };

inline constexpr std::size_t kMaxShareRows = 512;
inline constexpr std::size_t kMaxShareBytes = 1024 * 1024;
inline constexpr std::size_t kMaxFieldBytes = 4096;
/// Fixed per-share cost charged on top of the field bytes, so a flood of empty shares is
/// bounded by the byte budget as well as the row budget.
inline constexpr std::size_t kRowOverhead = 64;

struct Share {
    Proto proto = Proto::nfs;
    std::string name; ///< SMB share name; "-" (NFS exports are identified by path)
    std::string path;
    Access access = Access::unknown;
    std::optional<bool> anonymous;
    /// closed vocabulary: hidden, unavailable, special, sealed (macOS: SMB encryption
    /// required), no_root_squash, clients_<n>, and the Windows share kind (exactly one per
    /// row): disk, print, device, ipc, other; temporary.
    /// Windows `hidden` is a non-special share whose name ends in `$`
    std::vector<std::string> flags;
    std::string source;
};

inline std::string_view proto_token(Proto p) { return p == Proto::nfs ? "nfs" : "smb"; }

inline std::string_view access_token(Access a) {
    switch (a) {
    case Access::ro:
        return "ro";
    case Access::rw:
        return "rw";
    case Access::mixed:
        return "mixed";
    case Access::unknown:
        return "-";
    }
    return "-";
}

inline std::string_view state_token(SourceState s) {
    switch (s) {
    case SourceState::read:
        return "read";
    case SourceState::absent:
        return "absent";
    case SourceState::refused:
        return "refused";
    case SourceState::failed:
        return "failed";
    }
    return "failed";
}

namespace detail {

inline bool is_ws(char c) { return c == ' ' || c == '\t' || c == '\v' || c == '\f'; }

inline std::string lower(std::string_view s) {
    std::string out(s);
    // ASCII only, whatever the process locale (std::tolower follows setlocale).
    std::ranges::transform(out, out.begin(), [](unsigned char c) {
        return static_cast<char>(c >= 'A' && c <= 'Z' ? c + 32 : c);
    });
    return out;
}

inline std::vector<std::string_view> split(std::string_view s, char sep) {
    std::vector<std::string_view> out;
    std::size_t b = 0;
    for (;;) {
        const auto e = s.find(sep, b);
        if (e == std::string_view::npos) {
            out.push_back(s.substr(b));
            return out;
        }
        out.push_back(s.substr(b, e - b));
        b = e + 1;
    }
}

/// A field over kMaxFieldBytes is cut and the cut is recorded.
inline std::string cut(std::string_view v, bool& oversized) {
    if (v.size() > kMaxFieldBytes) {
        oversized = true;
        return std::string(v.substr(0, kMaxFieldBytes));
    }
    return std::string(v);
}

/// Charges the would-be (UNCUT) size of one share. false => budget refused: the caller marks
/// `truncated` and stops iterating, so nothing past the budget is ever materialised.
inline bool charge_share(yuzu::shared::RowByteBudget& b, std::size_t name_len, std::size_t path_len,
                         std::size_t flags_len) {
    return b.charge(name_len + path_len + flags_len + kRowOverhead);
}

inline std::optional<bool> parse_bool(std::string_view v) {
    const std::string l = lower(v);
    if (l == "yes" || l == "true" || l == "1")
        return true;
    if (l == "no" || l == "false" || l == "0")
        return false;
    return std::nullopt;
}

inline Access merge_access(Access a, Access b) {
    if (a == Access::unknown)
        return b;
    if (b == Access::unknown)
        return a;
    return a == b ? a : Access::mixed;
}

inline std::size_t flags_bytes(const std::vector<std::string>& f) {
    std::size_t n = 0;
    for (const auto& s : f)
        n += s.size() + 1;
    return n;
}

/// IPv4 literal in the inet_aton short forms nfs-utils accepts: 1-4 dot-separated non-empty
/// groups of digits; `zero_only` further requires every group to be all `0` (`0`, `0.0`,
/// `0.0.0.0`), the shape of an all-zero mask.
inline bool is_v4(std::string_view a, bool zero_only) {
    if (a.empty())
        return false;
    const auto groups = split(a, '.');
    return groups.size() <= 4 && std::ranges::all_of(groups, [zero_only](std::string_view g) {
               return !g.empty() && (zero_only ? g.find_first_not_of('0') == std::string_view::npos
                                               : std::ranges::all_of(g, [](unsigned char c) {
                                                     return std::isdigit(c) != 0;
                                                 }));
           });
}

/// IPv6 literal shape: every non-empty colon group 1-4 hex digits, exactly 8 groups without
/// `::` and at most 7 with it (`::`, `0::`, `1::`, `::1`, `0:0:0:0:0:0:0:0`); no stray single
/// colon. A second `::` leaves an empty group in the tail and fails the group check. The
/// dotted-tail form (`::ffff:0.0.0.0`) is not a hex group and is not recognised.
inline bool is_v6(std::string_view a) {
    const auto dc = a.find("::");
    std::size_t n = 0;
    const auto count = [&n](std::string_view part) {
        if (part.empty())
            return true;
        for (const auto g : split(part, ':')) {
            if (g.empty() || g.size() > 4 ||
                !std::ranges::all_of(g, [](unsigned char c) { return std::isxdigit(c) != 0; }))
                return false;
            ++n;
        }
        return true;
    };
    if (dc == std::string_view::npos)
        return count(a) && n == 8;
    return count(a.substr(0, dc)) && count(a.substr(dc + 2)) && n <= 7;
}

/// A client spec that admits everyone: empty, made only of `*`/`?`, or an IPv4/IPv6 literal
/// with a `/0` prefix or an all-zero dotted mask (`0.0.0.0/0`, `::/0`, `0/0`, `10.1.2.3/0`,
/// `1.2.3.4/0.0.0.0`). The mask decides, not the address: nfs-utils tests
/// `((a ^ b) & mask) == 0` for a dotted mask, so any literal with mask 0.0.0.0 matches every
/// client, whereas a `/0` PREFIX shifts by the full width (undefined; x86-64/aarch64 mask the
/// count to 0 and give an all-ones mask), so `/0` is world only by the conservative reading.
/// A bare zero address is one host, not the world, and a malformed address (`::::/0`,
/// `0.../0`, `:/0`, `host/0`) is none nfs-utils can resolve.
inline bool is_world_client(std::string_view c) {
    if (c.empty() || c.find_first_not_of("*?") == std::string_view::npos)
        return true;
    const auto slash = c.find('/');
    if (slash == std::string_view::npos)
        return false;
    const auto addr = c.substr(0, slash);
    return (is_v4(addr, false) || is_v6(addr)) && is_v4(c.substr(slash + 1), true);
}

/// Calls fn(logical_line) for each logical line: CR stripped, backslash-newline joined.
/// The first physical line of a logical line that begins (after blanks) with `#` or `;` is a
/// comment and never continues, so a trailing backslash in a comment cannot swallow the next
/// entry.
/// fn returns false to stop; nothing past that line is touched.
template <class Fn>
void for_each_logical_line(std::string_view text, Fn&& fn) {
    std::string line;
    std::size_t pos = 0;
    while (pos <= text.size()) {
        auto nl = text.find('\n', pos);
        const bool last = nl == std::string_view::npos;
        if (last)
            nl = text.size();
        std::string_view raw = text.substr(pos, nl - pos);
        pos = nl + 1;
        if (!raw.empty() && raw.back() == '\r')
            raw.remove_suffix(1);
        std::size_t f = 0;
        while (f < raw.size() && is_ws(raw[f]))
            ++f;
        const bool comment = line.empty() && f < raw.size() && (raw[f] == '#' || raw[f] == ';');
        if (!comment && !last && !raw.empty() && raw.back() == '\\') {
            line.append(raw.substr(0, raw.size() - 1));
            continue;
        }
        line.append(raw);
        const bool go = fn(std::string_view{line});
        line.clear();
        if (!go || last)
            return;
    }
}

struct Tok {
    std::string text;
    bool quoted = false;
    bool unterminated = false; ///< an opening `"` with no closing one before end of line
};

inline void skip_ws(std::string_view s, std::size_t& i) {
    while (i < s.size() && is_ws(s[i]))
        ++i;
}

/// One whitespace-delimited token (or one `"`-quoted string; exports(5) knows no other quote).
/// The only escape is `\NNN` (octal byte), as nfs-utils' xgettok decodes; any other backslash
/// stays literal. An unterminated quote marks the token `unterminated`; the caller skips the
/// line (nfsd never exports it either: xgettok runs the quote past the newline).
inline Tok next_token(std::string_view s, std::size_t& i) {
    Tok t;
    const char q = s[i] == '"' ? '"' : '\0';
    if (q != '\0') {
        t.quoted = true;
        ++i;
    }
    while (i < s.size()) {
        const char c = s[i];
        if (q != '\0' ? c == q : is_ws(c))
            break;
        if (c == '\\' && i + 1 < s.size()) {
            const char n = s[i + 1];
            if (n >= '0' && n <= '3' && i + 3 < s.size() && s[i + 2] >= '0' && s[i + 2] <= '7' &&
                s[i + 3] >= '0' && s[i + 3] <= '7') {
                t.text += static_cast<char>(((n - '0') << 6) | ((s[i + 2] - '0') << 3) |
                                            (s[i + 3] - '0'));
                i += 4;
                continue;
            }
        }
        t.text += c;
        ++i;
    }
    if (q != '\0') {
        if (i < s.size())
            ++i; // closing quote
        else
            t.unterminated = true;
    }
    return t;
}

} // namespace detail

// ---------------------------------------------------------------------------
// Linux exports(5)
// ---------------------------------------------------------------------------

struct ExportsParse {
    std::vector<Share> shares;
    bool truncated = false;
    bool field_oversized = false;
};

namespace detail {

struct ExportDefaults {
    Access access = Access::ro; // exports(5): ro unless rw is given
    bool root_squash = true;
    bool all_squash = false;
    /// all_squash maps every uid (root included) to anon, so root is exposed only when
    /// neither squash is in effect.
    [[nodiscard]] bool root_exposed() const { return !root_squash && !all_squash; }
};

/// Applies one export option to `d`; as nfs-utils applies options in order, the last of a
/// set/clear pair wins.
inline void apply_opt(std::string_view o, ExportDefaults& d) {
    if (o == "rw")
        d.access = Access::rw;
    else if (o == "ro")
        d.access = Access::ro;
    else if (o == "root_squash")
        d.root_squash = true;
    else if (o == "no_root_squash")
        d.root_squash = false;
    else if (o == "all_squash")
        d.all_squash = true;
    else if (o == "no_all_squash")
        d.all_squash = false;
}

/// Applies a comma-separated option list to defaults (a line-default `-opts` token).
inline void apply_default_opts(std::string_view csv, ExportDefaults& d) {
    for (const auto o : split(csv, ','))
        apply_opt(o, d);
}

/// Charges then materialises one NFS share. The budget is charged BEFORE the (cut) path is
/// built, so nothing past the budget is ever materialised. false => budget refused:
/// `out.truncated` is set and the caller stops iterating.
inline bool emit_nfs_share(ExportsParse& out, yuzu::shared::RowByteBudget& budget,
                           std::string_view source, std::string_view path, Access access,
                           bool anonymous, std::vector<std::string> flags) {
    if (!charge_share(budget, 1, path.size(), flags_bytes(flags))) {
        out.truncated = true;
        return false;
    }
    Share s;
    s.proto = Proto::nfs;
    s.name = "-";
    s.source = std::string(source);
    s.path = cut(path, out.field_oversized);
    s.access = access;
    s.anonymous = anonymous;
    s.flags = std::move(flags);
    out.shares.push_back(std::move(s));
    return true;
}

struct SpecResult {
    bool anonymous = false;
    Access access = Access::unknown;
    bool no_root_squash = false;
};

/// One client spec: `client`, `client(opts)` or `(opts)`. Options are scanned in order and
/// each `sec=` after the first starts a new segment that inherits the running option state
/// (nfs-utils: a flavour copies every ro/rw/squash option accumulated so far), so options
/// before the first `sec=` apply to every flavour. The spec's access is the segments'
/// common access, or `mixed` when they disagree.
inline SpecResult parse_spec(std::string_view tok, const ExportDefaults& defaults) {
    SpecResult r;
    const auto paren = tok.find('(');
    const std::string_view client = tok.substr(0, paren);
    r.anonymous = is_world_client(client);
    std::string_view opts;
    if (paren != std::string_view::npos) {
        opts = tok.substr(paren + 1);
        if (const auto close = opts.rfind(')'); close != std::string_view::npos)
            opts = opts.substr(0, close);
    }
    ExportDefaults cur = defaults;
    bool seen_sec = false;
    Access merged = Access::unknown;
    bool nrs = false;
    const auto push = [&] {
        merged = merge_access(merged, cur.access);
        nrs = nrs || cur.root_exposed();
    };
    for (const auto o : split(opts, ',')) {
        if (o.starts_with("sec=")) {
            if (seen_sec)
                push();
            seen_sec = true;
        } else {
            apply_opt(o, cur);
        }
    }
    push();
    r.access = merged;
    r.no_root_squash = nrs;
    return r;
}

} // namespace detail

/// Linux exports(5): `<path> [-opts] <client>[(opts)] ...`, `#` comments, backslash
/// continuation, quoted paths, octal escapes. A token starting with `-` is a line-default
/// option list applied to every LATER spec on the line. A spec with an empty or `*` client
/// is anonymous (so `host (rw)` yields host plus a world spec, the exports(5) footgun), as
/// does any other world-equivalent client (see is_world_client).
/// `source` is the wire source name ("exports" / "exports_d").
inline void parse_exports(std::string_view text, std::string_view source,
                          yuzu::shared::RowByteBudget& budget, ExportsParse& out) {
    detail::for_each_logical_line(text, [&](std::string_view line) {
        std::size_t i = 0;
        detail::skip_ws(line, i);
        if (i >= line.size() || line[i] == '#')
            return true;
        const auto path = detail::next_token(line, i);
        // nfsd export points are absolute: a pathless or option-first line is skipped.
        if (path.unterminated || path.text.empty() || path.text[0] != '/')
            return true;
        detail::ExportDefaults defaults;
        std::vector<detail::SpecResult> specs;
        bool bad = false;
        for (;;) {
            detail::skip_ws(line, i);
            if (i >= line.size() || line[i] == '#')
                break;
            const auto t = detail::next_token(line, i);
            if (t.unterminated) {
                bad = true;
                break;
            }
            if (t.text.empty())
                continue;
            if (!t.quoted && t.text[0] == '-')
                detail::apply_default_opts(std::string_view{t.text}.substr(1), defaults);
            else
                specs.push_back(detail::parse_spec(t.text, defaults));
        }
        if (bad)
            return true; // an unterminated quote: skip the whole line, emit nothing
        bool nrs = specs.empty() && defaults.root_exposed();
        bool anon = specs.empty();
        Access access = specs.empty() ? defaults.access : Access::unknown;
        for (const auto& sp : specs) {
            access = detail::merge_access(access, sp.access);
            anon = anon || sp.anonymous;
            nrs = nrs || sp.no_root_squash;
        }
        std::vector<std::string> flags;
        if (nrs)
            flags.emplace_back("no_root_squash");
        flags.emplace_back("clients_" + std::to_string(specs.size()));
        return detail::emit_nfs_share(out, budget, source, path.text, access, anon, std::move(flags));
    });
}

// ---------------------------------------------------------------------------
// BSD / macOS exports(5)
// ---------------------------------------------------------------------------

namespace detail {

/// One field as Apple's mountd `nextfield` bounds it: blanks (space, tab) skipped, a leading
/// single or double quote runs to the matching unescaped quote or the end of the entry (a
/// backslash makes the next character literal), an unquoted field ends at the first
/// unescaped space or tab. The raw field is returned, quotes kept; empty at end of entry.
inline std::string_view bsd_nextfield(std::string_view s, std::size_t& i) {
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t'))
        ++i;
    const std::size_t b = i;
    if (i >= s.size())
        return {};
    const char q = s[i];
    if (q == '\'' || q == '"') {
        ++i;
        bool esc = false;
        for (; i < s.size(); ++i) {
            if (esc)
                esc = false;
            else if (s[i] == '\\')
                esc = true;
            else if (s[i] == q)
                break;
        }
        if (i < s.size())
            ++i; // the closing quote
        return s.substr(b, i - b);
    }
    for (; i < s.size(); ++i) {
        if (s[i] == '\\') {
            if (++i >= s.size())
                break;
        } else if (s[i] == ' ' || s[i] == '\t') {
            break;
        }
    }
    return s.substr(b, i - b);
}

/// mountd `clean_pathname`: quotes removed, escapes resolved, an unquoted path ends at the
/// first blank, trailing slashes stripped (`/` itself is kept).
inline std::string bsd_clean_path(std::string_view f) {
    std::string s;
    char q = '\0';
    std::size_t p = 0;
    if (!f.empty() && (f[0] == '\'' || f[0] == '"')) {
        q = f[0];
        p = 1;
    }
    bool esc = false;
    for (; p < f.size(); ++p) {
        const char c = f[p];
        if (esc) {
            s += c;
            esc = false;
        } else if (q != '\0' && c == q) {
            break;
        } else if (c == '\\') {
            esc = true;
        } else if (q == '\0' && (c == ' ' || c == '\t')) {
            break;
        } else {
            s += c;
        }
    }
    while (s.size() > 1 && s.back() == '/')
        s.pop_back();
    return s;
}

/// macOS libc `inet_pton4`: exactly four decimal octets 0-255, nothing stray. A leading zero
/// is accepted (`01` is 1), as the macOS libc reads it (measured on 26.6.2). nullopt when the
/// value is invalid, else whether every octet is zero (the decoded bytes are never needed).
inline std::optional<bool> parse_dotted_quad(std::string_view s) {
    std::size_t octets = 0;
    unsigned cur = 0;
    bool saw_digit = false;
    bool zero = true;
    for (const char c : s) {
        if (c >= '0' && c <= '9') {
            cur = cur * 10 + static_cast<unsigned>(c - '0');
            if (cur > 255)
                return std::nullopt;
            if (!saw_digit) {
                if (++octets > 4)
                    return std::nullopt;
                saw_digit = true;
            }
        } else if (c == '.' && saw_digit) {
            if (octets == 4)
                return std::nullopt;
            zero = zero && cur == 0;
            cur = 0;
            saw_digit = false;
        } else {
            return std::nullopt;
        }
    }
    if (octets < 4)
        return std::nullopt;
    return zero && cur == 0;
}

/// macOS libc `inet_pton(AF_INET6)` as mountd's `get_net` calls it: a group is hex digits whose
/// value fits 16 bits (leading zeros are free, so `00000::` is valid), at most one `::`
/// (standing for at least one zero group), a dotted-quad tail only as the last 32 bits,
/// nothing stray. nullopt when the value is invalid, else whether every group is zero: a caller
/// needs the validity and the all-zero test, never the decoded address. Pure and portable (no
/// socket header); the Linux `is_v6` shape check is a different, stricter reading for a
/// different parser.
inline std::optional<bool> parse_v6(std::string_view s) {
    constexpr std::size_t kBytes = 16;
    std::size_t tp = 0; // bytes decoded so far
    bool dc = false;    // a `::` was seen
    bool zero = true;
    std::size_t i = 0;
    if (!s.empty() && s[0] == ':') {
        if (s.size() < 2 || s[1] != ':')
            return std::nullopt; // a lone leading colon
        i = 1;
    }
    std::size_t curtok = i; // start of the current group
    unsigned val = 0;
    bool saw_xdigit = false;
    for (; i < s.size(); ++i) {
        const char c = s[i];
        if (std::isxdigit(static_cast<unsigned char>(c)) != 0) {
            const unsigned d = c <= '9' ? static_cast<unsigned>(c - '0')
                                        : static_cast<unsigned>((c | 0x20) - 'a') + 10;
            val = (val << 4) | d;
            if (val > 0xffff)
                return std::nullopt;
            saw_xdigit = true;
        } else if (c == ':') {
            curtok = i + 1;
            if (!saw_xdigit) {
                if (dc)
                    return std::nullopt;
                dc = true;
                continue;
            }
            if (i + 1 == s.size() || tp + 2 > kBytes)
                return std::nullopt; // a trailing single colon, or too many groups
            tp += 2;
            zero = zero && val == 0;
            saw_xdigit = false;
            val = 0;
        } else if (c == '.' && tp + 4 <= kBytes) {
            const auto v4_zero = parse_dotted_quad(s.substr(curtok));
            if (!v4_zero)
                return std::nullopt;
            tp += 4;
            zero = zero && *v4_zero;
            saw_xdigit = false;
            break; // the tail ran to the end of the value
        } else {
            return std::nullopt;
        }
    }
    if (saw_xdigit) {
        if (tp + 2 > kBytes)
            return std::nullopt;
        tp += 2;
        zero = zero && val == 0;
    }
    if (dc) {
        if (tp == kBytes)
            return std::nullopt; // `::` must stand for at least one group
        tp = kBytes;
    }
    if (tp != kBytes)
        return std::nullopt;
    return zero;
}

/// Whether libc `inet_network` accepts a digit-led value (get_net's `isdigit(*cp)` branch):
/// 1-4 dot-separated parts, each decimal, octal (`0` prefix, no 8 or 9) or hex (`0x` / `0X`,
/// or a bare `x` after a dot), every part's 32-bit-wrapped value at most 0xff, and after the
/// last part the end of the value or a whitespace byte (a CR from a CRLF file is one, so a
/// trailing network or mask still parses there, unlike an IPv6 one). This is the macOS libc
/// reading (measured on 26.6.2): `0x0a` is valid, `0x0a000000` is not. The parts are packed one
/// byte each, as inet_network packs them, because get_net refuses the one packed value equal to
/// INADDR_NONE: four parts that are all 0xff (`255.255.255.255`, `0xff.0xff.0xff.0xff`,
/// `0377.0377.0377.0377`) are rejected, `255.255.255.254` is not. Past that check only the family
/// and validity matter here: an IPv4 network is never the world.
inline bool bsd_v4_literal(std::string_view v) {
    if (v.empty() || std::isdigit(static_cast<unsigned char>(v[0])) == 0)
        return false;
    std::size_t i = 0;
    std::uint32_t packed = 0;
    for (std::size_t parts = 0;; ++parts) {
        std::uint32_t val = 0;
        std::uint32_t base = 10;
        bool digit = false;
        if (i < v.size() && v[i] == '0') {
            digit = true;
            base = 8;
            ++i;
        }
        if (i < v.size() && (v[i] == 'x' || v[i] == 'X')) {
            base = 16;
            ++i;
        }
        for (; i < v.size(); ++i) {
            const char c = v[i];
            std::uint32_t d = 0;
            if (c >= '0' && c <= '9') {
                if (base == 8 && c >= '8')
                    return false;
                d = static_cast<std::uint32_t>(c - '0');
            } else if (base == 16 && std::isxdigit(static_cast<unsigned char>(c)) != 0) {
                d = static_cast<std::uint32_t>((c | 0x20) - 'a') + 10;
            } else {
                break;
            }
            val = val * base + d;
            digit = true;
        }
        if (!digit || parts >= 4 || val > 0xff)
            return false;
        packed = (packed << 8) | val;
        if (i < v.size() && v[i] == '.') {
            ++i;
            continue;
        }
        return (i == v.size() || std::isspace(static_cast<unsigned char>(v[i])) != 0) &&
               packed != 0xffffffffU; // INADDR_NONE: get_net's error value
    }
}

/// The family of a `-network` / `-mask` value in mountd's `get_net` order: an IPv6 literal
/// (`parse_v6`), a digit-led IPv4 form (inet_network), else a network name. A name is
/// classified by shape only and NEVER resolved (no resolver I/O here), so an unresolvable name
/// still counts as one client. A digit-led value that is no IPv4 form (`0.0.0.0/0`), an empty
/// value and a non-name (`::/0`) are ones Apple rejects, the whole line with them.
enum class BsdNetKind { v4, v6, name, rejected };

inline BsdNetKind bsd_net_kind(std::string_view v) {
    if (parse_v6(v).has_value())
        return BsdNetKind::v6;
    if (bsd_v4_literal(v))
        return BsdNetKind::v4;
    if (v.empty() || std::isdigit(static_cast<unsigned char>(v[0])) != 0)
        return BsdNetKind::rejected;
    // A name must be one getnetbyname could hold; anything else (`::/0`, `a/b`) Apple rejects.
    const bool plain = std::ranges::all_of(v, [](unsigned char c) {
        return std::isalnum(c) != 0 || c == '-' || c == '_' || c == '.';
    });
    return plain ? BsdNetKind::name : BsdNetKind::rejected;
}

/// Whether a `-network` / `-mask` pair admits every client under Apple's matching. An IPv6
/// network with no mask, or a mask whose groups are all zero (`::`, `0:0:0:0:0:0:0:0`,
/// `::0.0.0.0`), is the world: mountd zero-fills an absent IPv6 mask and both its masked
/// compare and the kernel's radix lookup (a zero mask is the default entry) then match every
/// address. An IPv4 network never is: a zero or absent IPv4 mask is replaced by the classful
/// one, so `0.0.0.0` exports 0.0.0.0/8. A named network or mask never is. `net` / `mask` are
/// empty when not given.
inline bool bsd_net_is_world(std::string_view net, std::string_view mask) {
    if (net.empty() || !parse_v6(net).has_value())
        return false;
    if (mask.empty())
        return true;
    return parse_v6(mask).value_or(false); // an invalid mask is not an all-zero one
}

/// Whether the user part of a `-maproot` / `-mapall` credential is root, as mountd's
/// `parsecred` resolves it: a digit- or `-`-led user is `getpwuid(atoi(user))`, so `0`, `00`,
/// `0x0` (atoi stops at the `x`) and `-0` are uid 0; any other user is root only when it is
/// the literal `root`. `atoi` is `(int)strtol`: only the low 32 bits of the value survive and
/// strtol saturates beyond +-2^63 (LONG_MIN truncates to 0, LONG_MAX to -1). `strtoll` is that
/// 64-bit strtol on every platform (`long` is 32-bit on LLP64 Windows). No account lookup is
/// made: a lone user (numeric or named) is never looked up, so one with no account still yields
/// a row though mountd drops the entry, and a non-root-named account that is uid 0 is not seen.
inline bool is_root_user(std::string_view user) {
    if (user.empty() || ((user[0] < '0' || user[0] > '9') && user[0] != '-'))
        return user == "root";
    return static_cast<int>(std::strtoll(std::string(user).c_str(), nullptr, 10)) == 0;
}

/// Darwin MAXPATHLEN: do_opt copies an `-fspath` value with strlcpy into a buffer this size and
/// refuses one whose length is this long or longer.
inline constexpr std::size_t kBsdMaxPathLen = 1024;

/// RPCMNT_NAMELEN: get_exportlist drops the whole entry when a cleaned directory path is longer
/// than this. It is not the `-fspath` bound above.
inline constexpr std::size_t kBsdNameLen = 255;

/// Whether parsecred can accept a `-maproot` / `-mapall` credential `user[:group...]` on any
/// host: the user is not empty and does not start with a quote (do_opt never strips quotes from
/// an option value, so `"0"` reaches getpwnam with its quote; an account name starting with a
/// quote is treated as unresolvable, the same premise as the empty user), and a group list that
/// is present is not made only of empty names (an empty name never resolves, so no group is
/// found and parsecred fails). A named user or group is host data and is not looked up.
inline bool bsd_cred_valid(std::string_view cred) {
    const auto colon = cred.find(':');
    const auto user = cred.substr(0, colon);
    if (user.empty() || user[0] == '"' || user[0] == '\'')
        return false;
    if (colon == std::string_view::npos)
        return true;
    const auto groups = cred.substr(colon + 1);
    return groups.empty() || groups.find_first_not_of(':') != std::string_view::npos;
}

/// Whether mountd's `get_sec_flavors` accepts a `-sec` value: colon-separated flavours, an empty
/// component skipped, a repeat of an accepted flavour skipped, and a component that is not
/// `sys` / `krb5` / `krb5i` / `krb5p` (exact case) voids the whole list, so `sys:bogus` is as bad
/// as `bogus`. At least one flavour must be accepted: `-sec=` and `-sec=:` are rejected. Apple's
/// scan also stops at NX_MAX_SEC_FLAVORS (5), which four distinct flavours can never reach, so
/// the cap is not modelled.
inline bool bsd_sec_valid(std::string_view v) {
    bool any = false;
    for (const auto flavor : split(v, ':')) {
        if (flavor.empty())
            continue;
        if (flavor != "sys" && flavor != "krb5" && flavor != "krb5i" && flavor != "krb5p")
            return false;
        any = true;
    }
    return any;
}

/// Whether do_opt accepts an `-fspath` value: it starts with `/` and is shorter than MAXPATHLEN.
inline bool bsd_fspath_valid(std::string_view v) {
    return !v.empty() && v[0] == '/' && v.size() < kBsdMaxPathLen;
}

/// Whether do_opt accepts an `-fsuuid` value: sixteen pairs of hex digits, one `-` allowed
/// before each pair. Nothing is tested after the sixteenth pair, so trailing text is accepted;
/// a short value runs into the terminator, which is no hex digit. do_opt's later `HEXTOC < 0`
/// check cannot fail once the hex-digit test has passed, so it is not modelled separately.
inline bool bsd_fsuuid_valid(std::string_view v) {
    const auto hex_at = [v](std::size_t k) {
        return k < v.size() && std::isxdigit(static_cast<unsigned char>(v[k])) != 0;
    };
    std::size_t i = 0;
    for (int pair = 0; pair < 16; ++pair, i += 2) {
        if (i < v.size() && v[i] == '-')
            ++i;
        if (!hex_at(i) || !hex_at(i + 1))
            return false;
    }
    return true;
}

/// What one accepted entry exports: its distinct paths and the facts they share.
struct BsdEntry {
    std::vector<std::string> paths;
    bool ro = false;
    bool offline = false;
    bool root = false;
    std::size_t hosts = 0;
    bool world = false;
    std::size_t clients = 0;
};

/// Parses one joined entry. false => Apple rejects it (no row, no token): an option or host
/// before any path, a path after an option or host, a repeated -network / -mask, a -network
/// together with a host, a malformed network or mask value (a name is never resolved, so an
/// unresolvable one is still accepted; an all-ones IPv4 value is INADDR_NONE, which get_net
/// refuses), mismatched families, a -mask without a -network, -maproot (or -root / -r) together
/// with -mapall (mountd `check_options`), a -maproot / -mapall / -root / -r credential parsecred
/// cannot accept on any host (an empty or quote-led user, a group list of only empty names; see
/// bsd_cred_valid), a bad -sec, -fspath or -fsuuid value (do_opt), and a cleaned path longer than
/// 255 bytes (get_exportlist).
inline bool parse_bsd_entry(std::string_view entry, BsdEntry& e) {
    std::size_t i = 0;
    std::string_view f = bsd_nextfield(entry, i);
    if (f.empty() || f[0] == '#')
        return false; // a comment or empty entry: no row, and no error either
    bool got_nondir = false;
    bool have_net = false;
    bool have_mask = false;
    bool have_maproot = false;
    bool have_mapall = false;
    std::string net;
    std::string mask;
    BsdNetKind net_kind = BsdNetKind::name;
    BsdNetKind mask_kind = BsdNetKind::name;
    for (; !f.empty(); f = bsd_nextfield(entry, i)) {
        if (f[0] == '-') {
            if (e.paths.empty())
                return false;
            got_nondir = true;
            // do_opt: comma-separated `name` / `name=value`; the LAST item without `=` takes
            // the next field as its value when that field exists and does not start with `-`.
            const auto items = split(f.substr(1), ',');
            for (std::size_t k = 0; k < items.size(); ++k) {
                std::string_view item = items[k];
                std::string_view arg;
                bool has_arg = false;
                bool from_next = false;
                std::size_t after_next = i;
                if (const auto eq = item.find('='); eq != std::string_view::npos) {
                    arg = item.substr(eq + 1);
                    item = item.substr(0, eq);
                    has_arg = true;
                } else if (k + 1 == items.size()) {
                    std::size_t j = i;
                    const auto nf = bsd_nextfield(entry, j);
                    if (!nf.empty() && nf[0] != '-') {
                        arg = nf;
                        has_arg = from_next = true;
                        after_next = j;
                    }
                }
                bool used_next = false;
                if (item == "ro" || item == "o") {
                    e.ro = true;
                } else if (has_arg && (item == "maproot" || item == "mapall" || item == "root" ||
                                       item == "r")) { // mountd do_opt: the credential-taking names
                    // parsecred resets the credential on every call, so the LAST mapping wins.
                    // A credential no host can satisfy (see bsd_cred_valid) fails do_opt and
                    // mountd drops the entry; a named user or group depends on the host and is
                    // not modelled.
                    if (!bsd_cred_valid(arg))
                        return false;
                    e.root = is_root_user(arg.substr(0, arg.find(':')));
                    if (item == "mapall")
                        have_mapall = true;
                    else
                        have_maproot = true;
                    used_next = from_next;
                } else if (has_arg && (item == "mask" || item == "m")) {
                    if (have_mask)
                        return false;
                    mask_kind = bsd_net_kind(arg);
                    if (mask_kind == BsdNetKind::rejected)
                        return false;
                    mask.assign(arg);
                    have_mask = true;
                    used_next = from_next;
                } else if (has_arg && (item == "network" || item == "n")) {
                    if (have_net)
                        return false;
                    net_kind = bsd_net_kind(arg);
                    if (net_kind == BsdNetKind::rejected)
                        return false;
                    net.assign(arg);
                    have_net = true;
                    used_next = from_next;
                } else if (has_arg && item == "sec") {
                    if (!bsd_sec_valid(arg))
                        return false;
                    used_next = from_next;
                } else if (item == "offline") {
                    e.offline = true;
                } else if (item == "fspath" || item == "fsuuid") {
                    // A value is checked, and a bad one rejects the entry; one taken from the
                    // next field is NOT consumed (mountd leaves it to be read as a field of its
                    // own, so a valid `-fspath /x` still leaves `/x` a path after an option). No
                    // value is only a warning.
                    if (has_arg &&
                        !(item == "fspath" ? bsd_fspath_valid(arg) : bsd_fsuuid_valid(arg)))
                        return false;
                } else if (item == "alldirs" || item == "32bitclients" || item == "manglednames") {
                    // accepted and ignored; a next-field value is NOT consumed
                } else {
                    break; // unrecognised (or a value-taking name with no value): the rest of
                           // this option field is dropped, as mountd drops it
                }
                if (used_next) {
                    i = after_next;
                    break;
                }
            }
        } else if (f[0] == '/' || ((f[0] == '\'' || f[0] == '"') && f.size() > 1 && f[1] == '/')) {
            if (got_nondir)
                return false; // "Directories must be first"
            auto p = bsd_clean_path(f);
            if (p.size() > kBsdNameLen)
                return false; // get_exportlist: "pathname too long", the whole entry is dropped
            // kMaxShareRows + 1 distinct paths already overflow the row budget (truncation is
            // signalled), so keeping more changes nothing; the size guard stops the duplicate
            // scan going quadratic on one very long line.
            if (e.paths.size() <= kMaxShareRows && std::ranges::find(e.paths, p) == e.paths.end())
                e.paths.push_back(std::move(p));
        } else {
            if (e.paths.empty())
                return false;
            got_nondir = true;
            ++e.hosts; // a host or netgroup: counted, never resolved or emitted
        }
    }
    if (e.paths.empty())
        return false;
    if (have_net && e.hosts > 0)
        return false;
    if (have_maproot && have_mapall)
        return false; // check_options: "-mapall and -maproot mutually exclusive"
    if (have_mask && !have_net)
        return false; // check_options: "-mask requires -network", hosts or not
    // get_net tries getnetbyname first and a resolved name is always AF_INET (an unresolved one
    // fails every later branch), so a name counts as IPv4 here and a v6 partner is a mismatch.
    if (have_net && have_mask && (net_kind == BsdNetKind::v6) != (mask_kind == BsdNetKind::v6))
        return false;
    e.clients = e.hosts + (have_net ? 1 : 0);
    e.world = (e.hosts == 0 && !have_net) || bsd_net_is_world(net, mask);
    return true;
}

} // namespace detail

/// macOS exports(5), modelled on Apple's mountd (best-effort: the rejections that need a host
/// lookup are not modelled): `<path>... [-opts] [hosts | -network net [-mask mask]]`. Entries are joined as get_export_entry joins them (trailing
/// spaces, tabs and backslashes stripped, and NOT a CR, which stays in the last field; a
/// stripped backslash appends the next physical line directly; a continuation still open at
/// end of file loses its entry), a field starting `#` makes the entry a comment, and fields
/// are bounded by nextfield (single or double quotes, backslash escapes). One share per
/// distinct path; hosts and netgroups are counted, never emitted. Access is `ro` for `-ro` /
/// `-o`, else `rw`; `-offline` flags the share `unavailable`; `no_root_squash` follows the
/// LAST `-maproot` / `-mapall` / `-root` / `-r` credential and is raised when its user is
/// root (see detail::is_root_user). Anonymous is Apple's world test (see
/// detail::bsd_net_is_world). A line Apple rejects yields no row and no token, as the Linux
/// parser skips a malformed line.
inline void parse_bsd_exports(std::string_view text, std::string_view source,
                              yuzu::shared::RowByteBudget& budget, ExportsParse& out) {
    std::string entry;
    std::size_t pos = 0;
    while (pos < text.size()) {
        auto nl = text.find('\n', pos);
        if (nl == std::string_view::npos)
            nl = text.size();
        std::string_view raw = text.substr(pos, nl - pos);
        pos = nl + 1;
        bool cont = false;
        // get_export_entry's strip set: space, tab, newline (already split on) and backslash.
        // Not CR: on a CRLF file Apple keeps it in the last field, and a `\` before it is no
        // continuation.
        while (!raw.empty() && (raw.back() == ' ' || raw.back() == '\t' || raw.back() == '\\')) {
            cont = cont || raw.back() == '\\';
            raw.remove_suffix(1);
        }
        entry.append(raw);
        if (cont || entry.empty())
            continue;
        detail::BsdEntry e;
        const bool ok = detail::parse_bsd_entry(entry, e);
        entry.clear();
        if (!ok)
            continue;
        for (const auto& p : e.paths) {
            std::vector<std::string> flags;
            if (e.offline)
                flags.emplace_back("unavailable");
            if (e.root)
                flags.emplace_back("no_root_squash");
            flags.emplace_back("clients_" + std::to_string(e.clients));
            if (!detail::emit_nfs_share(out, budget, source, p, e.ro ? Access::ro : Access::rw,
                                        e.world, std::move(flags)))
                return;
        }
    }
}

// ---------------------------------------------------------------------------
// Samba smb.conf
// ---------------------------------------------------------------------------

struct SmbConf {
    std::vector<Share> shares;
    bool registry_backend = false;      ///< `config backend = registry` / `registry shares = yes`
    bool include_present = false;       ///< any live `include =` or a global `config file =`
    bool usershares_configured = false; ///< global `usershare max shares` > 0 or `usershare path`
    bool usershares_off = false;        ///< global `usershare max shares` present and all zero
    /// any `copy =` line (not only the last) whose target is missing, `global`, cyclic, too long,
    /// too deep, defined after the copying share or re-opened after it (Samba snapshots the
    /// target where the directive stands and refuses a config whose copy source is not found)
    bool copy_unresolved = false;
    bool truncated = false;
    bool field_oversized = false;
};

namespace detail {

/// Collapses Samba parameter synonyms to one canonical key at insertion, so the INI map's
/// last-wins IS Samba's last-occurrence-wins. Keys lose case and all blanks;
/// writable/writeable/write ok become `readonly` with the value inverted; public becomes
/// `guestok`; browsable becomes `browseable`; directory becomes `path`.
inline void smb_canon(std::string& key, std::string& value) {
    std::string k;
    for (const char c : key)
        if (!is_ws(c))
            k += c;
    k = lower(k);
    if (k == "writable" || k == "writeable" || k == "writeok") {
        k = "readonly";
        if (const auto b = parse_bool(value))
            value = *b ? "no" : "yes";
    } else if (k == "public") {
        k = "guestok";
    } else if (k == "browsable") {
        k = "browseable";
    } else if (k == "directory") {
        k = "path";
    }
    key = std::move(k);
}

/// Joins backslash-newline continuations (CRLF tolerant). Comment lines never continue.
inline std::string join_continuations(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    for_each_logical_line(text, [&](std::string_view l) {
        out.append(l);
        out += '\n';
        return true;
    });
    return out;
}

using KvMap = std::map<std::string, std::string>;

inline const std::string* find_kv(const KvMap& sec, const std::string& key) {
    const auto f = sec.find(key);
    return f == sec.end() ? nullptr : &f->second;
}

/// Samba section names are case-insensitive and a re-opened section merges with last
/// assignment winning. Rewrites every `[Header]` to its lowercase form so parse_ini merges
/// all case variants into one map in source order, records the FIRST spelling of each
/// (what Samba keeps as the service name) in `display`, appends every header occurrence's
/// lower-cased name, reopenings included, to `occurrences` in source order, and records EVERY
/// `copy =` line of a non-global section as (section, value) in `copies` (the INI map keeps
/// only the last one, but Samba refuses the file over any unresolvable copy line).
inline std::string fold_section_headers(const std::string& text,
                                        std::map<std::string, std::string>& display,
                                        std::vector<std::string>& occurrences,
                                        std::vector<std::pair<std::string, std::string>>& copies) {
    std::string cur; // current section, lower-cased; empty before the first header or after a bad one
    std::string out;
    out.reserve(text.size());
    std::size_t pos = 0;
    while (pos < text.size()) {
        auto nl = text.find('\n', pos);
        if (nl == std::string::npos)
            nl = text.size();
        const std::string line = yuzu::shared::ini_trim(std::string_view(text).substr(pos, nl - pos));
        pos = nl + 1;
        const auto close = line.find(']');
        if (!line.empty() && line.front() == '[' && close != std::string::npos) {
            const auto name = yuzu::shared::ini_trim(std::string_view(line).substr(1, close - 1));
            const auto l = lower(name);
            display.emplace(l, name);
            occurrences.push_back(l);
            cur = l;
            out += '[' + l + "]\n";
        } else {
            if (line.empty() || line.front() == '#' || line.front() == ';') {
                // blank or comment: parse_ini skips it too
            } else if (line.front() == '[') {
                cur.clear(); // malformed header: parse_ini ignores its keys
            } else if (!cur.empty() && cur != "global") {
                if (const auto eq = line.find('='); eq != std::string::npos) {
                    std::string key{yuzu::shared::ini_trim(std::string_view(line).substr(0, eq))};
                    std::string value;
                    smb_canon(key, value);
                    if (key == "copy")
                        copies.emplace_back(cur, yuzu::shared::ini_trim(std::string_view(line).substr(eq + 1)));
                }
            }
            out += line;
            out += '\n';
        }
    }
    return out;
}

} // namespace detail

/// Parses smb.conf into shares. Lookup chain per parameter: own section, then the `copy =`
/// target chain (depth <= 8, cycle-safe; unresolved sets copy_unresolved, as does a target
/// defined after, or re-opened after, the copying share, or `copy = global`; every `copy =`
/// line is checked, not only the last one), then [global],
/// then Samba's built-in default (read only = yes, guest ok = no, browseable = yes,
/// available = yes). Lines before the first `[header]` belong to [global], as in Samba.
/// Registry backend, `include =` / `config file =` and usershares are DETECTED, never read.
/// A `write list` / `read list` is only checked for presence (its names are never read): it
/// makes access `mixed` when it contradicts the share default.
inline SmbConf parse_smb_conf(std::string_view text, yuzu::shared::RowByteBudget& budget) {
    SmbConf out;
    std::map<std::string, std::string> display; // lowercase section name -> first spelling
    std::vector<std::string> occurrences;       // every header, lower-cased, in source order
    std::vector<std::pair<std::string, std::string>> copies; // every (section, `copy =` value)
    const auto doc = yuzu::shared::parse_ini(
        "[global]\n" +
            detail::fold_section_headers(detail::join_continuations(text), display, occurrences, copies),
        &detail::smb_canon);
    const auto& global = doc.sections.at("global"); // always present: see the prefix above

    if (const auto* v = detail::find_kv(global, "configbackend"); v && detail::lower(*v) == "registry")
        out.registry_backend = true;
    if (const auto* v = detail::find_kv(global, "registryshares"))
        out.registry_backend = out.registry_backend || detail::parse_bool(*v).value_or(false);
    if (const auto* v = detail::find_kv(global, "usersharemaxshares")) {
        const std::string& t = *v; // parse_ini values arrive trimmed
        if (!t.empty() && std::ranges::all_of(t, [](unsigned char c) { return std::isdigit(c); })) {
            if (t.find_first_not_of('0') != std::string::npos)
                out.usershares_configured = true;
            else
                out.usershares_off = true;
        }
    }
    // An explicit all-zero `usershare max shares` disables usershares whatever the path says.
    if (const auto* v = detail::find_kv(global, "usersharepath"); v && !v->empty() && !out.usershares_off)
        out.usershares_configured = true;
    if (detail::find_kv(global, "configfile")) // a redirect of the same shape as `include =`
        out.include_present = true;
    for (const auto& sec : doc.sections)
        if (sec.second.contains("include"))
            out.include_present = true;

    constexpr int kMaxCopyDepth = 8;
    constexpr std::size_t kMaxCopyTargetBytes = 255;

    // Samba resolves `copy =` at parse time against the services loaded so far and snapshots
    // the target there, while `lookup` below reads the final merged file. The two agree only
    // when the target is wholly defined before the copying share and never re-opened after it,
    // so any other shape is flagged rather than modelled. The copier's FIRST header stands in
    // for the directive's position, which over-flags a copy placed in a later re-opening.
    std::map<std::string, std::size_t> first_at, last_at;
    for (std::size_t i = 0; i < occurrences.size(); ++i) {
        first_at.emplace(occurrences[i], i);
        last_at[occurrences[i]] = i;
    }
    for (const auto& [l, cp] : copies) {
        if (cp.size() > kMaxCopyTargetBytes) { // not a section name: no lower-casing
            out.copy_unresolved = true;
            continue;
        }
        const auto t = detail::lower(cp);
        const auto at = last_at.find(t);
        // Samba has no service named `global` to copy from. `at` is absent for [global] when it
        // has no header of its own, hence the explicit test.
        if (t == "global" || t == l || !doc.sections.contains(t) ||
            (at != last_at.end() && at->second > first_at.at(l)))
            out.copy_unresolved = true;
    }
    const auto lookup = [&](const std::string& own_lower, const std::string& key) -> const std::string* {
        std::vector<std::string> visited{own_lower};
        const detail::KvMap* cur = &doc.sections.at(own_lower);
        for (int depth = 0; cur != nullptr; ++depth) {
            if (const auto* v = detail::find_kv(*cur, key))
                return v;
            const auto* cp = detail::find_kv(*cur, "copy");
            if (cp == nullptr)
                break;
            if (cp->size() > kMaxCopyTargetBytes) { // not a section name: stop before lower-casing it per step
                out.copy_unresolved = true;
                break;
            }
            const auto l = detail::lower(*cp);
            const auto it = doc.sections.find(l);
            if (it == doc.sections.end() || depth >= kMaxCopyDepth ||
                std::ranges::find(visited, l) != visited.end()) {
                out.copy_unresolved = true;
                break;
            }
            visited.push_back(l);
            cur = &it->second;
        }
        return detail::find_kv(global, key);
    };

    for (const auto& l : doc.section_order) {
        if (l == "global" || l.empty())
            continue;
        Share s;
        s.proto = Proto::smb;
        s.source = "smb_conf";
        const auto* path = lookup(l, "path");
        const auto* ro = lookup(l, "readonly");
        const auto* wlist = lookup(l, "writelist");
        const auto* rlist = lookup(l, "readlist");
        const auto* guest = lookup(l, "guestok");
        const auto* browse = lookup(l, "browseable");
        const auto* avail = lookup(l, "available");
        if (browse && !detail::parse_bool(*browse).value_or(true))
            s.flags.emplace_back("hidden");
        if (avail && !detail::parse_bool(*avail).value_or(true))
            s.flags.emplace_back("unavailable");
        if (l == "homes" || l == "printers" || l == "print$")
            s.flags.emplace_back("special");
        if (!detail::charge_share(budget, display.at(l).size(), path ? path->size() : 1,
                                  detail::flags_bytes(s.flags))) {
            out.truncated = true;
            break;
        }
        s.name = detail::cut(display.at(l), out.field_oversized);
        s.path = path ? detail::cut(*path, out.field_oversized) : "-";
        const bool rw = ro && !detail::parse_bool(*ro).value_or(true);
        s.access = rw ? Access::rw : Access::ro;
        // A list only matters when it contradicts the default: ro + write list, rw + read list.
        if (const auto* list = rw ? rlist : wlist; list && !list->empty())
            s.access = Access::mixed;
        s.anonymous = guest ? detail::parse_bool(*guest).value_or(false) : false;
        out.shares.push_back(std::move(s));
    }
    return out;
}

// ---------------------------------------------------------------------------
// macOS `sharing -l -f json`
// ---------------------------------------------------------------------------

/// What `sharing -l` prints when no share point exists. Taken from the tool's string table
/// (/usr/sbin/sharing), not observed live: an empty-host capture may widen what is recognised.
inline constexpr std::string_view kNoSharePoints = "No share point records.";

struct SharingParse {
    std::vector<Share> shares;
    bool recognised = false; ///< a JSON object, `{}` or the exact no-records text
    std::size_t malformed_records = 0;
    bool truncated = false;
    bool field_oversized = false;
};

namespace detail {

/// An integer member as a number; nullopt when absent or any other type.
inline std::optional<long long> json_flag(const nlohmann::json& rec, const char* key) {
    const auto it = rec.find(key);
    if (it == rec.end())
        return std::nullopt;
    if (it->is_number_integer())
        return it->get<long long>();
    return std::nullopt;
}

} // namespace detail

/// The JSON object `sharing -l -f json` prints, keyed by record name. Each member must be an
/// object with a string `path`, else it is counted in malformed_records and skipped (valid
/// siblings are still emitted). The name is `smb_name` when a string, else the key. A record
/// with `smb_shared` 0 is flagged `unavailable`, `smb_sealed` 1 (encryption required) `sealed`;
/// `smb_read_only` gives the access, `smb_guest_access` the anonymous flag. Empty or
/// whitespace-only text is NOT recognised: no capture shows what an empty host prints, so it is
/// a named failure upstream, never an empty success. ACLs and permissions are never read.
inline SharingParse parse_sharing_json(std::string_view text, yuzu::shared::RowByteBudget& budget) {
    SharingParse out;
    constexpr std::string_view kBlanks = " \t\r\n";
    const auto b = text.find_first_not_of(kBlanks);
    if (b == std::string_view::npos)
        return out;
    const auto trimmed = text.substr(b, text.find_last_not_of(kBlanks) - b + 1);
    if (trimmed == kNoSharePoints) {
        out.recognised = true;
        return out;
    }
    const auto j = nlohmann::json::parse(text.begin(), text.end(), nullptr, false);
    if (j.is_discarded() || !j.is_object())
        return out;
    out.recognised = true;
    for (const auto& [key, rec] : j.items()) {
        if (!rec.is_object()) {
            ++out.malformed_records;
            continue;
        }
        const auto pit = rec.find("path");
        if (pit == rec.end() || !pit->is_string()) {
            ++out.malformed_records;
            continue;
        }
        const std::string& path = pit->get_ref<const std::string&>();
        std::string_view name = key;
        if (const auto n = rec.find("smb_name"); n != rec.end() && n->is_string())
            name = n->get_ref<const std::string&>();
        std::vector<std::string> flags;
        if (const auto v = detail::json_flag(rec, "smb_shared"); v && *v == 0)
            flags.emplace_back("unavailable");
        if (const auto v = detail::json_flag(rec, "smb_sealed"); v && *v == 1)
            flags.emplace_back("sealed");
        if (!detail::charge_share(budget, name.size(), path.size(), detail::flags_bytes(flags))) {
            out.truncated = true;
            break;
        }
        Share s;
        s.proto = Proto::smb;
        s.source = "sharing";
        s.name = detail::cut(name, out.field_oversized);
        s.path = detail::cut(path, out.field_oversized);
        s.flags = std::move(flags);
        if (const auto v = detail::json_flag(rec, "smb_read_only"); v && *v == 1)
            s.access = Access::ro;
        else if (v && *v == 0)
            s.access = Access::rw;
        if (const auto v = detail::json_flag(rec, "smb_guest_access"); v && (*v == 0 || *v == 1))
            s.anonymous = *v == 1;
        out.shares.push_back(std::move(s));
    }
    return out;
}

// ---------------------------------------------------------------------------
// Row formatters
// ---------------------------------------------------------------------------

/// One free wire field: "-" when empty, else scrubbed of NUL and anything outside strictly
/// well-formed UTF-8 (scrub_wire_bytes; NEVER sanitize_utf8, which passes overlong,
/// surrogate and out-of-range sequences, #4864) then passed through safe_output_field: a
/// backslash is folded to '/' (so a Windows path reads C:/Users), CR/LF fold to spaces and a
/// pipe is escaped.
[[nodiscard]] inline std::string wire_field(std::string_view v) {
    if (v.empty())
        return "-";
    std::string s{v};
    yuzu::shared::scrub_wire_bytes(s);
    return yuzu::util::safe_output_field(s);
}

/// `share|<nfs|smb>|<name>|<path>|<ro|rw|mixed|->|<true|false|->|<flags csv or ->|<source>`
[[nodiscard]] inline std::string share_row(const Share& s) {
    std::string flags;
    for (const auto& f : s.flags) {
        if (!flags.empty())
            flags += ',';
        flags += f;
    }
    std::string r = "share|";
    r += proto_token(s.proto);
    r += '|';
    r += wire_field(s.name);
    r += '|';
    r += wire_field(s.path);
    r += '|';
    r += access_token(s.access);
    r += '|';
    r += s.anonymous ? (*s.anonymous ? "true" : "false") : "-";
    r += '|';
    r += flags.empty() ? std::string{"-"} : flags;
    r += '|';
    r += wire_field(s.source);
    return r;
}

/// `source|<exports|exports_d|smb_conf|netshareenum|sharing>|<state>|<share count or ->`
[[nodiscard]] inline std::string source_row(std::string_view kind, SourceState state,
                                            std::optional<std::size_t> count = std::nullopt) {
    std::string r = "source|";
    r += kind;
    r += '|';
    r += state_token(state);
    r += '|';
    r += count ? std::to_string(*count) : std::string{"-"};
    return r;
}

/// `*.exports`, not a dotfile, a single path component.
inline bool is_exports_name(std::string_view n) {
    constexpr std::string_view ext = ".exports";
    return n.size() > ext.size() && n.ends_with(ext) && n.front() != '.' &&
           n.find('/') == std::string_view::npos;
}

} // namespace yuzu::shares
