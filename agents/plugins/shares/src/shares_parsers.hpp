#pragma once

// shares_parsers.hpp -- pure parsers and row formatters for the shares plugin: what this
// host CONFIGURES to serve over SMB/NFS. Header-only and portable so the unit tests run on
// every host; no file I/O, no subprocess, no OS header.
//
//   parse_exports       Linux exports(5) grammar (/etc/exports, /etc/exports.d/*.exports)
//   parse_bsd_exports   BSD/macOS exports(5) grammar (/etc/exports read by macOS nfsd)
//   parse_smb_conf      Samba smb.conf: share sections, synonyms, `copy =` and [global]
//                       inheritance, plus detection of the parts this plugin does not read
//   parse_sharing_json  macOS `sharing -l -f json`
//
// NAMES AND PATHS ONLY, NEVER ACLs. NFS client host lists are never emitted: a share carries
// `clients_<n>` and an `anonymous` flag only. Every parser charges a caller-owned
// yuzu::shared::RowByteBudget BEFORE materialising a share and stops at the first refusal,
// so allocation is bounded by the budget plus the input, independent of section count.
//
// The `status|list|...` row is NOT built here; shares_legs.hpp's report_list owns it.

#include <ini_parse.hpp>
#include <row_byte_budget.hpp>
#include <wire_utf8.hpp>
#include <yuzu/string_utils.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <map>
#include <optional>
#include <string>
#include <string_view>
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
    std::vector<std::string> flags; ///< closed vocabulary, see flags_csv
    std::string source;
};

/// Closed flag vocabulary: hidden, unavailable, special, sealed, no_root_squash, clients_<n>.
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
    std::ranges::transform(out, out.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
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

/// Calls fn(logical_line) for each logical line: CR stripped, backslash-newline joined.
/// A physical line that begins (after blanks) with `#` or `;` is a comment and never
/// continues, so a trailing backslash in a comment cannot swallow the next entry.
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
};

inline void skip_ws(std::string_view s, std::size_t& i) {
    while (i < s.size() && is_ws(s[i]))
        ++i;
}

/// One whitespace-delimited token (or one quoted string). Escapes: `\NNN` octal byte, and
/// backslash before a blank, quote or backslash yields that character; any other backslash
/// stays literal. An unterminated quote runs to end of line.
inline Tok next_token(std::string_view s, std::size_t& i) {
    Tok t;
    const char q = (s[i] == '"' || s[i] == '\'') ? s[i] : '\0';
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
            if (n == ' ' || n == '\t' || n == '"' || n == '\'' || n == '\\') {
                t.text += n;
                i += 2;
                continue;
            }
        }
        t.text += c;
        ++i;
    }
    if (q != '\0' && i < s.size())
        ++i; // closing quote
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
    bool no_root_squash = false;
};

/// Applies one export option to `d`; true when it set the access (rw / ro).
inline bool apply_opt(std::string_view o, ExportDefaults& d) {
    if (o == "rw") {
        d.access = Access::rw;
        return true;
    }
    if (o == "ro") {
        d.access = Access::ro;
        return true;
    }
    if (o == "no_root_squash")
        d.no_root_squash = true;
    return false;
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
/// each `sec=` starts a new segment that inherits the line defaults; the spec's access is
/// the segments' common access, or `mixed` when they disagree. Options before the first
/// `sec=` form a segment only when they set ro/rw themselves.
inline SpecResult parse_spec(std::string_view tok, const ExportDefaults& defaults) {
    SpecResult r;
    const auto paren = tok.find('(');
    const std::string_view client = tok.substr(0, paren);
    r.anonymous = client.empty() || client == "*";
    std::string_view opts;
    if (paren != std::string_view::npos) {
        opts = tok.substr(paren + 1);
        if (const auto close = opts.rfind(')'); close != std::string_view::npos)
            opts = opts.substr(0, close);
    }
    ExportDefaults cur = defaults;
    bool seen_sec = false, explicit_access = false;
    Access merged = Access::unknown;
    bool nrs = defaults.no_root_squash;
    const auto push = [&] {
        merged = merge_access(merged, cur.access);
        nrs = nrs || cur.no_root_squash;
    };
    for (const auto o : split(opts, ',')) {
        if (o.starts_with("sec=")) {
            if (seen_sec || explicit_access)
                push();
            seen_sec = true;
            cur = defaults;
            explicit_access = false;
        } else {
            explicit_access = apply_opt(o, cur) || explicit_access;
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
/// is anonymous (so `host (rw)` yields host plus a world spec, the exports(5) footgun).
/// `source` is the wire source name ("exports" / "exports_d").
inline void parse_exports(std::string_view text, std::string_view source,
                          yuzu::shared::RowByteBudget& budget, ExportsParse& out) {
    detail::for_each_logical_line(text, [&](std::string_view line) {
        std::size_t i = 0;
        detail::skip_ws(line, i);
        if (i >= line.size() || line[i] == '#')
            return true;
        const auto path = detail::next_token(line, i);
        if (path.text.empty())
            return true;
        detail::ExportDefaults defaults;
        std::vector<detail::SpecResult> specs;
        for (;;) {
            detail::skip_ws(line, i);
            if (i >= line.size() || line[i] == '#')
                break;
            const auto t = detail::next_token(line, i);
            if (t.text.empty())
                continue;
            if (!t.quoted && t.text[0] == '-')
                detail::apply_default_opts(std::string_view{t.text}.substr(1), defaults);
            else
                specs.push_back(detail::parse_spec(t.text, defaults));
        }
        bool nrs = false;
        bool anon = specs.empty();
        Access access = specs.empty() ? defaults.access : Access::unknown;
        nrs = specs.empty() && defaults.no_root_squash;
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

/// BSD exports(5) as read by macOS nfsd (man exports, macOS 26.6): `<path>... [-opts]
/// [hosts | -network net [-mask mask]]`. Leading tokens that start with `/` or a quote are
/// the exported paths (one share each); `-ro`/`-o` is read-only (default rw), `-offline`
/// flags the share unavailable, `-network`/`-mask` take the next token unless written
/// `-network=...`; every other `-option` (maproot, mapall, alldirs, sec, ...) is ignored;
/// remaining tokens are hosts or netgroups and are only COUNTED. No host and no network
/// means the share is exported to the world (anonymous).
inline void parse_bsd_exports(std::string_view text, std::string_view source,
                              yuzu::shared::RowByteBudget& budget, ExportsParse& out) {
    detail::for_each_logical_line(text, [&](std::string_view line) {
        std::size_t i = 0;
        std::vector<std::string> paths;
        for (;;) {
            detail::skip_ws(line, i);
            if (i >= line.size() || (line[i] != '/' && line[i] != '"' && line[i] != '\''))
                break;
            paths.push_back(detail::next_token(line, i).text);
        }
        if (paths.empty())
            return true;
        bool ro = false, offline = false;
        std::size_t clients = 0;
        for (;;) {
            detail::skip_ws(line, i);
            if (i >= line.size() || line[i] == '#')
                break;
            const auto t = detail::next_token(line, i);
            if (!t.quoted && t.text.size() > 1 && t.text[0] == '-') {
                const auto eq = t.text.find('=');
                const std::string name = t.text.substr(1, eq == std::string::npos ? eq : eq - 1);
                if (name == "ro" || name == "o") {
                    ro = true;
                } else if (name == "offline") {
                    offline = true;
                } else if (name == "network" || name == "mask") {
                    if (name == "network")
                        ++clients;
                    if (eq == std::string::npos) { // value is the next token
                        detail::skip_ws(line, i);
                        if (i < line.size())
                            (void)detail::next_token(line, i);
                    }
                }
            } else if (!t.text.empty()) {
                ++clients;
            }
        }
        for (const auto& p : paths) {
            std::vector<std::string> flags;
            if (offline)
                flags.emplace_back("unavailable");
            flags.emplace_back("clients_" + std::to_string(clients));
            if (!detail::emit_nfs_share(out, budget, source, p, ro ? Access::ro : Access::rw,
                                        clients == 0, std::move(flags)))
                return false;
        }
        return true;
    });
}

// ---------------------------------------------------------------------------
// Samba smb.conf
// ---------------------------------------------------------------------------

struct SmbConf {
    std::vector<Share> shares;
    bool registry_backend = false;      ///< `config backend = registry` / `registry shares = yes`
    bool include_present = false;       ///< any live `include =`
    bool usershares_configured = false; ///< global `usershare max shares` > 0 or `usershare path`
    bool copy_unresolved = false;       ///< a `copy =` target missing, cyclic or too deep
    bool truncated = false;
    bool field_oversized = false;
    std::string usershare_path; ///< the global `usershare path` value, if any
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
            k += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
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

inline const std::string* find_kv(const std::vector<const KvMap*>& secs, const std::string& key) {
    for (auto it = secs.rbegin(); it != secs.rend(); ++it)
        if (const auto f = (*it)->find(key); f != (*it)->end())
            return &f->second;
    return nullptr;
}

} // namespace detail

/// Parses smb.conf into shares. Lookup chain per parameter: own section, then the `copy =`
/// target chain (depth <= 8, cycle-safe; unresolved sets copy_unresolved), then [global],
/// then Samba's built-in default (read only = yes, guest ok = no, browseable = yes,
/// available = yes). Registry backend, `include =` and usershares are DETECTED, never read.
// ponytail: sections whose names differ only by case are merged in first-seen order; a
// re-opened section under another case spelling is applied after the earlier ones even when
// the file interleaves them. Upgrade to per-key source order if a real file needs it.
inline SmbConf parse_smb_conf(std::string_view text, yuzu::shared::RowByteBudget& budget) {
    SmbConf out;
    const std::string joined = detail::join_continuations(text);
    const auto doc = yuzu::shared::parse_ini(joined, &detail::smb_canon);

    std::map<std::string, std::vector<const detail::KvMap*>> by_lower;
    std::vector<std::pair<std::string, std::string>> order; // (lower, display)
    for (const auto& name : doc.section_order) {
        const auto l = detail::lower(name);
        auto& v = by_lower[l];
        if (v.empty())
            order.emplace_back(l, name);
        v.push_back(&doc.sections.at(name));
    }
    static const std::vector<const detail::KvMap*> kNone;
    const auto g = by_lower.find("global");
    const auto& global = g == by_lower.end() ? kNone : g->second;

    if (const auto* v = detail::find_kv(global, "configbackend"); v && detail::lower(*v) == "registry")
        out.registry_backend = true;
    if (const auto* v = detail::find_kv(global, "registryshares"))
        out.registry_backend = out.registry_backend || detail::parse_bool(*v).value_or(false);
    if (const auto* v = detail::find_kv(global, "usersharemaxshares")) {
        const std::string& t = *v; // parse_ini values arrive trimmed
        if (!t.empty() && std::ranges::all_of(t, [](unsigned char c) { return std::isdigit(c); }) &&
            t.find_first_not_of('0') != std::string::npos)
            out.usershares_configured = true;
    }
    if (const auto* v = detail::find_kv(global, "usersharepath"); v && !v->empty()) {
        out.usershares_configured = true;
        out.usershare_path = detail::cut(*v, out.field_oversized);
    }
    for (const auto& sec : doc.sections)
        if (sec.second.contains("include"))
            out.include_present = true;

    constexpr int kMaxCopyDepth = 8;
    const auto lookup = [&](const std::string& own_lower, const std::string& key) -> const std::string* {
        std::vector<std::string> visited{own_lower};
        const std::vector<const detail::KvMap*>* cur = &by_lower.at(own_lower);
        for (int depth = 0; cur != nullptr; ++depth) {
            if (const auto* v = detail::find_kv(*cur, key))
                return v;
            const auto* cp = detail::find_kv(*cur, "copy");
            if (cp == nullptr)
                break;
            const auto l = detail::lower(*cp);
            const auto it = by_lower.find(l);
            if (it == by_lower.end() || depth >= kMaxCopyDepth ||
                std::ranges::find(visited, l) != visited.end()) {
                out.copy_unresolved = true;
                break;
            }
            visited.push_back(l);
            cur = &it->second;
        }
        return detail::find_kv(global, key);
    };

    for (const auto& [l, display] : order) {
        if (l == "global")
            continue;
        Share s;
        s.proto = Proto::smb;
        s.source = "smb_conf";
        const auto* path = lookup(l, "path");
        const auto* ro = lookup(l, "readonly");
        const auto* guest = lookup(l, "guestok");
        const auto* browse = lookup(l, "browseable");
        const auto* avail = lookup(l, "available");
        if (browse && !detail::parse_bool(*browse).value_or(true))
            s.flags.emplace_back("hidden");
        if (avail && !detail::parse_bool(*avail).value_or(true))
            s.flags.emplace_back("unavailable");
        if (l == "homes" || l == "printers" || l == "print$")
            s.flags.emplace_back("special");
        if (!detail::charge_share(budget, display.size(), path ? path->size() : 1,
                                  detail::flags_bytes(s.flags))) {
            out.truncated = true;
            break;
        }
        s.name = detail::cut(display, out.field_oversized);
        s.path = path ? detail::cut(*path, out.field_oversized) : "-";
        s.access = (ro && !detail::parse_bool(*ro).value_or(true)) ? Access::rw : Access::ro;
        s.anonymous = guest ? detail::parse_bool(*guest).value_or(false) : false;
        out.shares.push_back(std::move(s));
    }
    return out;
}

// ---------------------------------------------------------------------------
// macOS `sharing -l -f json`
// ---------------------------------------------------------------------------

struct SharingParse {
    std::vector<Share> shares;
    bool recognised = false;
    std::size_t malformed_records = 0;
    bool truncated = false;
    bool field_oversized = false;
};

namespace detail {

inline std::optional<long long> json_flag(const nlohmann::json& rec, const char* key) {
    const auto it = rec.find(key);
    if (it == rec.end())
        return std::nullopt;
    if (it->is_boolean())
        return it->get<bool>() ? 1 : 0;
    if (it->is_number_integer())
        return it->get<long long>();
    return std::nullopt;
}

} // namespace detail

/// Whitespace-only text or `{}` is a recognised empty list; anything that is not a JSON
/// object is unrecognised. Each entry must be an object carrying a string `path`, else it
/// is counted in malformed_records and skipped (valid siblings are still emitted).
inline SharingParse parse_sharing_json(std::string_view text, yuzu::shared::RowByteBudget& budget) {
    SharingParse out;
    if (text.find_first_not_of(" \t\r\n") == std::string_view::npos) {
        out.recognised = true;
        return out;
    }
    const auto j = nlohmann::json::parse(text.begin(), text.end(), nullptr, false);
    if (j.is_discarded() || !j.is_object())
        return out;
    out.recognised = true;
    for (const auto& [key, rec] : j.items()) {
        if (!rec.is_object() || !rec.contains("path") || !rec["path"].is_string()) {
            ++out.malformed_records;
            continue;
        }
        const std::string& path = rec["path"].get_ref<const std::string&>();
        std::string_view name = key;
        if (const auto n = rec.find("smb_name"); n != rec.end() && n->is_string())
            name = n->get_ref<const std::string&>();
        Share s;
        s.proto = Proto::smb;
        s.source = "sharing";
        if (const auto v = detail::json_flag(rec, "smb_shared"); v && *v == 0)
            s.flags.emplace_back("unavailable");
        if (const auto v = detail::json_flag(rec, "smb_sealed"); v && *v == 1)
            s.flags.emplace_back("sealed");
        if (!detail::charge_share(budget, name.size(), path.size(), detail::flags_bytes(s.flags))) {
            out.truncated = true;
            break;
        }
        s.name = detail::cut(name, out.field_oversized);
        s.path = detail::cut(path, out.field_oversized);
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
/// surrogate and out-of-range sequences, #4864) then pipe/backslash/CRLF-escaped.
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

/// `source|<exports|exports_d|smb_conf|sharing>|<state>|<share count or ->`
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
