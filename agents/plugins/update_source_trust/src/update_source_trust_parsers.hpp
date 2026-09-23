/**
 * update_source_trust_parsers.hpp -- the PURE, PORTABLE parsing + row-formatting
 * layer for update_source_trust.
 *
 * Everything here is a free function over plain data: no OS calls, no file
 * I/O, no logging, no platform headers, no <dirent.h>/<fcntl.h>. It compiles
 * and is unit-tested on EVERY OS (test_update_source_trust_parsers.cpp). The
 * walk/read shell lives in update_source_trust_linux_parsers.hpp (POSIX only)
 * and feeds these functions bytes.
 *
 * WHAT THIS PLUGIN REPORTS. One read-only action, `sources`: FACTS about how a
 * device's package/update sources are configured to trust signing authorities.
 * No enforcement, no verdicts, no fetching -- an unsigned or rogue repo is a
 * fact a consumer can query, never a decision made here.
 *
 * WIRE ROWS (one pipe-delimited row per line; a status row always comes first).
 * Every row of a kind carries the same field count, "-" where a value is
 * absent. Free text is untrusted OS-supplied data and goes through
 * yuzu::util::safe_output_field (lossy on backslash -> '/', pipes escaped);
 * every apt_source field a URL could land in (uris, suites, components,
 * signed_by) additionally has any `user:pass@` userinfo redacted -- per field:
 * a whole-row pass would scan across the `|` separators.
 *
 *   status|sources|<supported|constrained|unsupported>|<reason or ->
 *   apt_source|<file>|<format one_line|deb822>|<types>|<uris>|<suites>|<components>|<signed_by>|<trusted>|<allow_insecure>|<enabled>
 *   apt_keyring|<path>|<scope>|<format armored|binary|empty|unmodelled>|<size_bytes>
 *   rpm_repo|...   macos_swu|...   wsus|...
 *       PLANNED shapes, never emitted here (not read yet): the
 *       rpm/dnf .repo family, the macOS Software Update leg, the Windows WSUS
 *       leg) and is documented in content/definitions/update_source_trust.yaml.
 *
 * TRISTATE. Every boolean-ish OS value maps to exactly one of
 * yes | no | unset | unmodelled. `unset` = the key is absent (a fact: the
 * source did not say); `unmodelled` = the key is present but its value is not
 * one this plugin recognises (present-but-unreadable is NOT absent and is NOT
 * silently coerced). `apt_source.enabled` is yes/no/unmodelled (deb822's
 * default is enabled). For apt_source `types` a token that is neither `deb`
 * nor `deb-src` is emitted as the literal `unmodelled`.
 *
 * `signed_by` is the raw Signed-By/signed-by value with whitespace collapsed
 * (paths and/or fingerprints), the literal `inline_key` when a deb822
 * Signed-By embeds a PGP key block (the key material is never emitted), or "-"
 * when absent (apt then falls back to its global trusted keyrings -- reported
 * as the fact it is).
 *
 * KNOWN LIMITS (facts-only scope, stated so no consumer infers more):
 *   - apt: /usr/share/keyrings is not inventoried; keys referenced by
 *     Signed-By are reported by path, not resolved or fingerprinted.
 *   - rpm/dnf (the .repo files under /etc/yum.repos.d) and macOS Software
 *     Update are not read at all yet. The Linux
 *     leg reports the rpm family as a planned constraint rather than as absent.
 *   - URLs: userinfo (`user:pass@`) is redacted; a secret carried in a query
 *     string cannot be recognised and is emitted as written.
 */
#pragma once

#include <yuzu/string_utils.hpp>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::update_source_trust {

// ── vocab ────────────────────────────────────────────────────────────────

enum class Tri { yes, no, unset, unmodelled };

[[nodiscard]] constexpr std::string_view tri_token(Tri t) noexcept {
    switch (t) {
    case Tri::yes:        return "yes";
    case Tri::no:         return "no";
    case Tri::unset:      return "unset";
    case Tri::unmodelled: return "unmodelled";
    }
    return "unmodelled";
}

enum class StatusState { supported, constrained, unsupported };

[[nodiscard]] constexpr std::string_view status_token(StatusState s) noexcept {
    switch (s) {
    case StatusState::supported:   return "supported";
    case StatusState::constrained: return "constrained";
    case StatusState::unsupported: return "unsupported";
    }
    return "constrained";
}

enum class AptFormat { one_line, deb822 };

[[nodiscard]] constexpr std::string_view apt_format_token(AptFormat f) noexcept {
    return f == AptFormat::deb822 ? "deb822" : "one_line";
}

enum class KeyFormat { armored, binary, empty, unmodelled };

[[nodiscard]] constexpr std::string_view key_format_token(KeyFormat f) noexcept {
    switch (f) {
    case KeyFormat::armored:    return "armored";
    case KeyFormat::binary:     return "binary";
    case KeyFormat::empty:      return "empty";
    case KeyFormat::unmodelled: return "unmodelled";
    }
    return "unmodelled";
}

// ── small text helpers ───────────────────────────────────────────────────

[[nodiscard]] inline bool is_ascii_space(char c) noexcept {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

[[nodiscard]] inline std::string_view trim(std::string_view s) noexcept {
    while (!s.empty() && is_ascii_space(s.front()))
        s.remove_prefix(1);
    while (!s.empty() && is_ascii_space(s.back()))
        s.remove_suffix(1);
    return s;
}

[[nodiscard]] inline std::string ascii_lower(std::string_view s) {
    std::string out{s};
    for (char& c : out)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

[[nodiscard]] inline std::vector<std::string_view> split_ws(std::string_view s) {
    std::vector<std::string_view> out;
    std::size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && is_ascii_space(s[i]))
            ++i;
        const std::size_t start = i;
        while (i < s.size() && !is_ascii_space(s[i]))
            ++i;
        if (i > start)
            out.push_back(s.substr(start, i - start));
    }
    return out;
}

/// Runs of whitespace (including newlines from continuation lines) collapse to
/// one space; leading/trailing whitespace dropped.
[[nodiscard]] inline std::string collapse_ws(std::string_view s) {
    std::string out;
    for (auto tok : split_ws(s)) {
        if (!out.empty())
            out += ' ';
        out.append(tok);
    }
    return out;
}

/// Maps a boolean-ish config value to a Tri. nullopt (key absent) -> unset;
/// the union of the apt (yes/no/true/false/with/without/on/off/enable/disable/
/// 1/0) and yum/dnf (1/0/yes/no/true/false/on/off/enabled/disabled)
/// vocabularies -> yes/no; anything else (including an empty value) ->
/// unmodelled, never silently coerced. The rpm/dnf leg uses this union; the
/// apt legs use tri_from_apt_value, because apt does not accept the yum words.
[[nodiscard]] inline Tri tri_from_value(std::optional<std::string_view> v) {
    if (!v)
        return Tri::unset;
    const std::string s = ascii_lower(trim(*v));
    for (std::string_view t : {"yes", "true", "1", "on", "enabled", "enable", "with"})
        if (s == t)
            return Tri::yes;
    for (std::string_view t : {"no", "false", "0", "off", "disabled", "disable", "without"})
        if (s == t)
            return Tri::no;
    return Tri::unmodelled;
}

/// apt's own boolean vocabulary (apt-pkg StringToBool): 1/yes/true/with/on/
/// enable and 0/no/false/without/off/disable, case-insensitive. The yum/dnf
/// words `enabled`/`disabled` are NOT apt vocabulary: apt ignores
/// `Trusted: enabled` and leaves an `Enabled: disabled` source active, so a
/// value outside this list is `unmodelled` (present, not one apt honours).
[[nodiscard]] inline Tri tri_from_apt_value(std::optional<std::string_view> v) {
    if (!v)
        return Tri::unset;
    const std::string s = ascii_lower(trim(*v));
    for (std::string_view t : {"yes", "true", "1", "on", "enable", "with"})
        if (s == t)
            return Tri::yes;
    for (std::string_view t : {"no", "false", "0", "off", "disable", "without"})
        if (s == t)
            return Tri::no;
    return Tri::unmodelled;
}

/// Replaces the `user[:pass]@` userinfo of every `scheme://authority` in `text`
/// with `REDACTED@`. Repo definitions routinely embed credentials in baseurl /
/// URIs; a trust-posture fact must never carry them onto the wire. The
/// authority ends at the first `/` or whitespace, exactly as apt's URI parser
/// ends it: a `?` or `#` is a legal character of a password (apt resolves
/// `http://bob:pa?ss@host/`), so stopping there would leak the tail. The
/// userinfo is everything up to the LAST `@` of the authority; a query string
/// containing `@` therefore over-redacts, which is the safe direction.
[[nodiscard]] inline std::string redact_url_userinfo(std::string_view text) {
    std::string out;
    std::size_t pos = 0;
    while (pos < text.size()) {
        const std::size_t scheme = text.find("://", pos);
        if (scheme == std::string_view::npos) {
            out.append(text.substr(pos));
            break;
        }
        const std::size_t auth_start = scheme + 3;
        out.append(text.substr(pos, auth_start - pos));
        std::size_t auth_end = auth_start;
        while (auth_end < text.size() && text[auth_end] != '/' && !is_ascii_space(text[auth_end]))
            ++auth_end;
        const std::string_view authority = text.substr(auth_start, auth_end - auth_start);
        const std::size_t at = authority.rfind('@');
        if (at != std::string_view::npos) {
            out += "REDACTED@";
            out.append(authority.substr(at + 1));
        } else {
            out.append(authority);
        }
        pos = auth_end;
    }
    return out;
}

/// Length of the well-formed UTF-8 scalar starting at s[i] (1-4), or 0 when the
/// byte there is NUL or does not start one (stray continuation byte, overlong
/// form, surrogate, above U+10FFFF, truncated sequence).
[[nodiscard]] inline std::size_t utf8_scalar_len(std::string_view s, std::size_t i) noexcept {
    const auto at = [&](std::size_t k) { return static_cast<unsigned char>(s[k]); };
    const auto cont = [&](std::size_t k) { return k < s.size() && (at(k) & 0xC0u) == 0x80u; };
    const unsigned c = at(i);
    if (c == 0)
        return 0;
    if (c < 0x80)
        return 1;
    if (c >= 0xC2 && c <= 0xDF)
        return cont(i + 1) ? 2 : 0;
    if (c >= 0xE0 && c <= 0xEF) {
        if (!cont(i + 1) || !cont(i + 2))
            return 0;
        if ((c == 0xE0 && at(i + 1) < 0xA0) || (c == 0xED && at(i + 1) >= 0xA0))
            return 0; // overlong / UTF-16 surrogate
        return 3;
    }
    if (c >= 0xF0 && c <= 0xF4) {
        if (!cont(i + 1) || !cont(i + 2) || !cont(i + 3))
            return 0;
        if ((c == 0xF0 && at(i + 1) < 0x90) || (c == 0xF4 && at(i + 1) >= 0x90))
            return 0; // overlong / above U+10FFFF
        return 4;
    }
    return 0;
}

/// Replaces every byte that may not reach the wire -- NUL (the plugin ABI
/// carries C strings, so a NUL cuts the row) and anything outside well-formed
/// UTF-8 (the ABI is UTF-8; an invalid byte makes the whole response
/// unparseable downstream) -- with '?'. Returns how many bytes were replaced.
inline std::size_t scrub_wire_bytes(std::string& s) {
    std::size_t replaced = 0;
    for (std::size_t i = 0; i < s.size();) {
        const std::size_t n = utf8_scalar_len(s, i);
        if (n == 0) {
            s[i] = '?';
            ++replaced;
            ++i;
        } else {
            i += n;
        }
    }
    return replaced;
}

/// One wire field: "-" when empty, otherwise the untrusted text scrubbed of
/// bytes that cannot cross the plugin ABI (scrub_wire_bytes) and escaped for the
/// shared server decoder (safe_output_field; lossy on backslash by design).
[[nodiscard]] inline std::string field(std::string_view v) {
    if (v.empty())
        return "-";
    std::string s{v};
    scrub_wire_bytes(s);
    return yuzu::util::safe_output_field(s);
}

[[nodiscard]] inline std::string url_field(std::string_view v) {
    return field(redact_url_userinfo(v));
}

// ── errno -> failure-detail token ────────────────────────────────────────

enum class IoStage { open_file, read_file, open_dir };

/// `errno` from a failed open/read on a path this plugin walks -> the stable
/// `<detail>` half of a `<os>:<source>:<detail>` failure token. ENOENT is NOT
/// mapped here: it means "genuinely absent", which every caller handles as zero
/// rows (supported), never as a failure. Every other errno is a real constraint
/// and must reach the ConstraintAccumulator.
[[nodiscard]] constexpr std::string_view errno_detail(int err, IoStage stage) noexcept {
    switch (err) {
    case EACCES:
    case EPERM:  return "permission_denied";
    case ELOOP:  return "symlink_refused";
    case ENOTDIR: return "not_a_directory";
    case EISDIR: return "not_regular";
    case EIO:    return "io_error";
    default: break;
    }
    switch (stage) {
    case IoStage::open_file: return "open_failed";
    case IoStage::read_file: return "read_failed";
    case IoStage::open_dir:  return "dir_open_failed";
    }
    return "open_failed";
}

// ── apt sources ──────────────────────────────────────────────────────────

/// One `apt_source` row's facts (file + format are supplied by the caller).
struct AptSourceFacts {
    std::string types;      // space-joined: deb | deb-src | unmodelled
    std::string uris;       // space-joined, raw (redacted at format time)
    std::string suites;
    std::string components; // empty when the entry has none
    std::string signed_by;  // "" when absent; "inline_key" for an embedded key block
    Tri trusted = Tri::unset;
    Tri allow_insecure = Tri::unset;
    Tri enabled = Tri::yes;
};

struct AptParseResult {
    std::vector<AptSourceFacts> sources;
    /// Entries that could not be parsed into a row. A caller MUST surface a
    /// non-zero count as a constraint (an unparsed source is a source whose
    /// trust this plugin could not report).
    std::size_t malformed = 0;
};

[[nodiscard]] inline std::string apt_type_token(std::string_view t) {
    const std::string l = ascii_lower(t);
    if (l == "deb")
        return "deb";
    if (l == "deb-src")
        return "deb-src";
    return "unmodelled";
}

/// The Signed-By value as reported: an embedded PGP key block is never echoed.
[[nodiscard]] inline std::string apt_signed_by_value(std::string_view raw) {
    if (raw.find("BEGIN PGP") != std::string_view::npos)
        return "inline_key";
    return collapse_ws(raw);
}

/// Splits on ASCII whitespace like split_ws, except that whitespace inside a
/// `[...]` group does not split: apt keeps a bracket group inside ONE word
/// (`cdrom:[Debian GNU/Linux 12 ...]/`, and the `[opt=val ...]` block). An
/// unterminated `[` runs to the end of the text.
[[nodiscard]] inline std::vector<std::string_view> split_apt_words(std::string_view s) {
    std::vector<std::string_view> out;
    std::size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && is_ascii_space(s[i]))
            ++i;
        const std::size_t start = i;
        int depth = 0;
        for (; i < s.size(); ++i) {
            if (s[i] == '[')
                ++depth;
            else if (s[i] == ']' && depth > 0)
                --depth;
            else if (depth == 0 && is_ascii_space(s[i]))
                break;
        }
        if (i > start)
            out.push_back(s.substr(start, i - start));
    }
    return out;
}

/// The text before the first `#` that is outside a `[...]` group. apt ends a
/// line at ANY such `#` (`main#c` is `main`; `http://h/a#b suite main` is a
/// malformed entry), not only at one preceded by whitespace.
[[nodiscard]] inline std::string_view strip_apt_comment(std::string_view line) noexcept {
    int depth = 0;
    for (std::size_t i = 0; i < line.size(); ++i) {
        if (line[i] == '[')
            ++depth;
        else if (line[i] == ']' && depth > 0)
            --depth;
        else if (line[i] == '#' && depth == 0)
            return line.substr(0, i);
    }
    return line;
}

/// Parses classic sources.list text (`deb [opt=val ...] uri suite [component...]`).
/// Comments (whole-line or after an entry, see strip_apt_comment) are ignored.
/// Options are `key=value` tokens inside `[...]` (also `key+=`/`key-=`); only
/// signed-by, trusted and allow-insecure are surfaced, and their KEYS are
/// case-sensitive exactly as in apt (`[Trusted=yes]` is ignored by apt, so it
/// is ignored here). A `+=`/`-=` on a surfaced key is `unmodelled`: the effective
/// value depends on earlier options, which this plugin does not evaluate. Every
/// other option, and any option token without '=', is tolerated and ignored. A
/// line needs a type, a uri and a suite; an unterminated `[` or too few words
/// is malformed.
[[nodiscard]] inline AptParseResult parse_apt_one_line(std::string_view text) {
    AptParseResult res;
    std::size_t pos = 0;
    while (pos <= text.size()) {
        const std::size_t nl = text.find('\n', pos);
        std::string_view line =
            text.substr(pos, nl == std::string_view::npos ? std::string_view::npos : nl - pos);
        pos = (nl == std::string_view::npos) ? text.size() + 1 : nl + 1;

        line = trim(strip_apt_comment(trim(line)));
        if (line.empty())
            continue;

        const auto words = split_apt_words(line);
        std::size_t next = 1; // index of the uri word
        std::string_view options;
        if (words.size() > 1 && words[1].front() == '[') {
            if (words[1].size() < 2 || words[1].back() != ']') {
                ++res.malformed; // unterminated option block
                continue;
            }
            options = words[1].substr(1, words[1].size() - 2);
            next = 2;
        }
        if (words.size() < next + 2) { // type + uri + suite
            ++res.malformed;
            continue;
        }

        AptSourceFacts f;
        f.types = apt_type_token(words[0]);
        f.uris = std::string{words[next]};
        f.suites = std::string{words[next + 1]};
        for (std::size_t i = next + 2; i < words.size(); ++i) {
            if (!f.components.empty())
                f.components += ' ';
            f.components.append(words[i]);
        }
        for (auto opt : split_ws(options)) {
            const std::size_t eq = opt.find('=');
            if (eq == std::string_view::npos)
                continue; // tolerated
            std::string_view key = opt.substr(0, eq);
            const bool appends = !key.empty() && (key.back() == '+' || key.back() == '-');
            if (appends)
                key.remove_suffix(1);
            const std::string_view val = opt.substr(eq + 1);
            if (key == "signed-by")
                f.signed_by = appends ? "unmodelled" : apt_signed_by_value(val);
            else if (key == "trusted")
                f.trusted = appends ? Tri::unmodelled : tri_from_apt_value(val);
            else if (key == "allow-insecure")
                f.allow_insecure = appends ? Tri::unmodelled : tri_from_apt_value(val);
            // any other option: tolerated, ignored
        }
        res.sources.push_back(std::move(f));
    }
    return res;
}

/// Parses deb822 .sources text: stanzas separated by EMPTY lines (a line of
/// only whitespace is a continuation line for apt, so it does not end a stanza);
/// `Field: value` lines; continuation lines start with space/tab (a lone " ."
/// is a blank line inside the value); whole-line `#` comments skipped; field
/// names case-insensitive; a repeated field keeps its LAST value, as in apt.
/// Only `Signed-By`, `Trusted` and `Enabled` are surfaced. `Allow-Insecure` is
/// NOT read: apt ignores it in deb822 (only the one-line `[allow-insecure=yes]`
/// is honoured), so `allow_insecure` is always `unset` here. A stanza needs
/// Types, URIs and Suites (Components is optional -- an absolute-path Suites
/// has none); otherwise it, and any non-field line, is malformed.
[[nodiscard]] inline AptParseResult parse_apt_deb822(std::string_view text) {
    AptParseResult res;
    using Stanza = std::vector<std::pair<std::string, std::string>>;
    std::vector<Stanza> stanzas;
    Stanza cur;

    std::size_t pos = 0;
    while (pos <= text.size()) {
        const std::size_t nl = text.find('\n', pos);
        std::string_view line =
            text.substr(pos, nl == std::string_view::npos ? std::string_view::npos : nl - pos);
        pos = (nl == std::string_view::npos) ? text.size() + 1 : nl + 1;
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);

        if (line.empty()) {
            if (!cur.empty())
                stanzas.push_back(std::move(cur));
            cur.clear();
            continue;
        }
        if (line.front() == '#')
            continue;
        if (line.front() == ' ' || line.front() == '\t') {
            if (cur.empty()) {
                ++res.malformed;
                continue;
            }
            std::string_view c = trim(line);
            if (c == ".")
                c = {};
            cur.back().second += '\n';
            cur.back().second.append(c);
            continue;
        }
        const std::size_t colon = line.find(':');
        if (colon == std::string_view::npos || trim(line.substr(0, colon)).empty()) {
            ++res.malformed;
            continue;
        }
        cur.emplace_back(ascii_lower(trim(line.substr(0, colon))),
                         std::string{trim(line.substr(colon + 1))});
    }
    if (!cur.empty())
        stanzas.push_back(std::move(cur));

    for (const auto& st : stanzas) {
        auto get = [&](std::string_view k) -> std::optional<std::string_view> {
            for (auto it = st.rbegin(); it != st.rend(); ++it)
                if (it->first == k)
                    return std::string_view{it->second};
            return std::nullopt;
        };
        const auto types = get("types");
        const auto uris = get("uris");
        const auto suites = get("suites");
        if (!types || !uris || !suites || collapse_ws(*types).empty() ||
            collapse_ws(*uris).empty() || collapse_ws(*suites).empty()) {
            ++res.malformed;
            continue;
        }
        AptSourceFacts f;
        for (auto tok : split_ws(*types)) {
            if (!f.types.empty())
                f.types += ' ';
            f.types += apt_type_token(tok);
        }
        f.uris = collapse_ws(*uris);
        f.suites = collapse_ws(*suites);
        if (auto c = get("components"))
            f.components = collapse_ws(*c);
        if (auto s = get("signed-by"))
            f.signed_by = apt_signed_by_value(*s);
        f.trusted = tri_from_apt_value(get("trusted"));
        if (auto e = get("enabled"))
            f.enabled = tri_from_apt_value(e);
        res.sources.push_back(std::move(f));
    }
    return res;
}

// ── apt directory file names ─────────────────────────────────────────────

/// apt's own rule for the files of its `*.d` directories (sources.list.d,
/// trusted.gpg.d; `GetListOfFilesInDir`): hidden names and any name with a
/// character outside [A-Za-z0-9_.-] are skipped ("bad filenames ala
/// run-parts"). The walk applies it BEFORE the suffix test so the plugin
/// reports exactly the files apt itself reads and no phantom sources.
[[nodiscard]] inline bool apt_dir_name_ok(std::string_view name) noexcept {
    if (name.empty() || name.front() == '.')
        return false;
    for (const char c : name) {
        const bool alnum = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
        if (!alnum && c != '_' && c != '-' && c != '.')
            return false;
    }
    return true;
}

// ── apt keyrings ─────────────────────────────────────────────────────────

/// Classifies the first bytes of a keyring file. OpenPGP binary packets always
/// have bit 7 of the first byte set; ASCII armor starts with its BEGIN line.
/// Anything else (text that is not armor) is `unmodelled`, not guessed at.
[[nodiscard]] inline KeyFormat sniff_keyring(std::string_view head) noexcept {
    if (head.empty())
        return KeyFormat::empty;
    const std::string_view t = trim(head);
    if (t.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"))
        return KeyFormat::armored;
    if ((static_cast<unsigned char>(head.front()) & 0x80u) != 0)
        return KeyFormat::binary;
    return KeyFormat::unmodelled;
}

// ── row formatters ───────────────────────────────────────────────────────
//
// Return the row WITHOUT a trailing newline (append_output() inserts the
// separator between successive writes).

[[nodiscard]] inline std::string format_status_row(StatusState s, std::string_view reason) {
    std::string out = "status|sources|";
    out.append(status_token(s));
    out += '|';
    out += field(reason);
    return out;
}

[[nodiscard]] inline std::string format_apt_source_row(std::string_view file, AptFormat fmt,
                                                       const AptSourceFacts& f) {
    std::string out = "apt_source|";
    out += field(file);
    out += '|';
    out.append(apt_format_token(fmt));
    out += '|';
    out += field(f.types);
    out += '|';
    out += url_field(f.uris);
    out += '|';
    out += url_field(f.suites);
    out += '|';
    out += url_field(f.components);
    out += '|';
    out += url_field(f.signed_by);
    out += '|';
    out.append(tri_token(f.trusted));
    out += '|';
    out.append(tri_token(f.allow_insecure));
    out += '|';
    out.append(tri_token(f.enabled));
    return out;
}

[[nodiscard]] inline std::string format_apt_keyring_row(std::string_view path,
                                                        std::string_view scope, KeyFormat fmt,
                                                        std::uint64_t size_bytes) {
    std::string out = "apt_keyring|";
    out += field(path);
    out += '|';
    out += field(scope);
    out += '|';
    out.append(key_format_token(fmt));
    out += '|';
    out += std::to_string(size_bytes);
    return out;
}

// ── file text -> rows (pure composition the walk shell delegates to) ─────────
//
// The Linux walk shell only OPENS and READS files; turning file text into wire
// rows is this pure function, so the whole text -> row path is unit-tested on
// every OS without touching a filesystem. It returns the number of malformed
// entries it had to drop; the caller records a non-zero count as a constraint
// (an unparsed source is never silently absent).

[[nodiscard]] inline std::size_t apt_rows_from_text(std::string_view logical_file, AptFormat fmt,
                                                    std::string_view text,
                                                    std::vector<std::string>& rows) {
    const AptParseResult parsed =
        fmt == AptFormat::deb822 ? parse_apt_deb822(text) : parse_apt_one_line(text);
    for (const auto& s : parsed.sources)
        rows.push_back(format_apt_source_row(logical_file, fmt, s));
    return parsed.malformed;
}

} // namespace yuzu::update_source_trust
