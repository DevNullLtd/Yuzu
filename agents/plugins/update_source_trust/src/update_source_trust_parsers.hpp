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
 * No other shape exists yet: the rpm/dnf, macOS and Windows legs are planned and
 * report a status row only.
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

#include <wire_utf8.hpp>
#include <yuzu/string_utils.hpp>

#include <algorithm>
#include <cctype>
#include <charconv>
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

/// Maps an apt boolean-ish config value to a Tri. nullopt (key absent) ->
/// unset. apt's own vocabulary (apt-pkg StringToBool): 1/yes/true/with/on/enable
/// and 0/no/false/without/off/disable, case-insensitive. The yum/dnf words
/// `enabled`/`disabled` are NOT apt vocabulary: apt ignores `Trusted: enabled`
/// and leaves an `Enabled: disabled` source active, so a value outside the list
/// is `unmodelled` (present, not one apt honours), never silently coerced.
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
        std::size_t depth = 0;
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

/// Splits an option block (the inside of `[...]`) into `key=value` tokens like
/// split_ws, except that whitespace inside a matching pair of double quotes does
/// not split: apt de-quotes a quoted option VALUE as one token even when it
/// contains a space (`[signed-by="/etc/apt/a b.gpg"]`). An unterminated quote
/// runs to the end of the block, same shape as split_apt_words' bracket handling.
[[nodiscard]] inline std::vector<std::string_view> split_apt_options(std::string_view s) {
    std::vector<std::string_view> out;
    std::size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && is_ascii_space(s[i]))
            ++i;
        const std::size_t start = i;
        bool quoted = false;
        for (; i < s.size(); ++i) {
            if (s[i] == '"')
                quoted = !quoted;
            else if (!quoted && is_ascii_space(s[i]))
                break;
        }
        if (i > start)
            out.push_back(s.substr(start, i - start));
    }
    return out;
}

/// The %XX-decoded form of `s`: used only to decode a surfaced option's VALUE
/// (apt does the same before reading signed-by/trusted/allow-insecure). A '%'
/// that is not followed by two hex digits stays as written.
[[nodiscard]] inline std::string percent_decoded(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        unsigned byte = 0;
        if (s[i] == '%' && i + 2 < s.size() &&
            std::from_chars(s.data() + i + 1, s.data() + i + 3, byte, 16).ptr == s.data() + i + 3) {
            out += static_cast<char>(byte);
            i += 2;
        } else {
            out += s[i];
        }
    }
    return out;
}

/// One word of a URI list with the `user[:pass]@` userinfo replaced by
/// `REDACTED@`. Every position below is a RAW byte offset into `word` -- NOTHING
/// is percent-decoded before the split. An earlier version decoded the whole
/// word first, so a %XX-encoded byte in the password (`bob:%2fSEKR3T@host`)
/// could be read as the path separator and stop the authority scan short,
/// missing the '@' entirely and returning the WHOLE credential unredacted; real
/// apt does not decode %XX when it locates the authority either (verified: its
/// own resolved URI still shows `%2fSEKR3T` literally), so working on raw bytes
/// matches apt AND cannot under-run. The one place apt's lexer does recognise a
/// percent form is the scheme separator itself (`http%3a//u:pw@h/` resolves as
/// `http://u:pw@h/`, verified), so ':' and "%3a"/"%3A" are both accepted there,
/// whichever comes first. From there the authority ends at the first raw '/'
/// OUTSIDE a `[...]` group -- an encoded slash (%2f/%2F) does NOT end it, which
/// is what makes the authority span reach the real '@' even when a password
/// contains one. The userinfo is everything in that authority before its LAST
/// '@'; a query string or path holding a secret is not syntactically a userinfo
/// and is emitted as written (documented) -- widening the search past the
/// authority boundary would redact a bare '@' in a path (`h.example/a@b`),
/// which is not a credential and must stay untouched.
[[nodiscard]] inline std::string redact_apt_word(std::string_view word) {
    std::size_t colon = word.find(':');
    std::size_t colon_len = 1;
    for (const std::string_view enc : {std::string_view{"%3a"}, std::string_view{"%3A"}}) {
        const std::size_t p = word.find(enc);
        if (p != std::string_view::npos && (colon == std::string_view::npos || p < colon)) {
            colon = p;
            colon_len = 3;
        }
    }
    if (colon == std::string_view::npos)
        return std::string{word}; // no scheme, so no authority
    std::size_t begin = colon + colon_len;
    if (word.compare(begin, 2, "//") == 0)
        begin += 2;
    std::size_t end = begin;
    bool in_bracket = false;
    for (; end < word.size() && (word[end] != '/' || in_bracket); ++end) {
        if (word[end] == '[')
            in_bracket = true;
        else if (word[end] == ']')
            in_bracket = false;
    }
    const std::size_t at = std::string_view{word}.substr(begin, end - begin).rfind('@');
    if (at == std::string_view::npos)
        return std::string{word};
    return std::string{word.substr(0, begin)} + "REDACTED@" + std::string{word.substr(begin + at + 1)};
}

/// Every word of `text` (split as apt splits a source line, so a `[...]` group
/// stays whole) through redact_apt_word, re-joined with single spaces.
[[nodiscard]] inline std::string redact_url_userinfo(std::string_view text) {
    std::string out;
    for (const auto w : split_apt_words(text)) {
        if (!out.empty())
            out += ' ';
        out += redact_apt_word(w);
    }
    return out;
}

/// The conservative fallback for text whose bytes had to be replaced: a replaced
/// byte can turn text into a URL shape apt never saw (`http:<NUL>//u:pw@h/`
/// becomes `http:?//u:pw@h/`), which no faithful split recognises. Every word
/// containing an '@' loses everything up to its LAST '@'.
[[nodiscard]] inline std::string redact_after_last_at(std::string_view text) {
    std::string out;
    for (const auto w : split_apt_words(text)) {
        if (!out.empty())
            out += ' ';
        const std::size_t at = w.rfind('@');
        if (at == std::string_view::npos)
            out.append(w);
        else
            out.append("REDACTED@").append(w.substr(at + 1));
    }
    return out;
}

/// One wire field: "-" when empty, otherwise the untrusted text scrubbed of
/// bytes that cannot cross the plugin ABI (scrub_wire_bytes) and escaped for the
/// shared server decoder (safe_output_field; lossy on backslash by design).
[[nodiscard]] inline std::string field(std::string_view v) {
    if (v.empty())
        return "-";
    std::string s{v};
    yuzu::shared::scrub_wire_bytes(s);
    return yuzu::util::safe_output_field(s);
}

/// `field` that also adds to `altered` the number of bytes scrub_wire_bytes replaced
/// in what it emits (a NUL or a byte outside well-formed UTF-8).
[[nodiscard]] inline std::string field(std::string_view v, std::size_t& altered) {
    altered += yuzu::shared::count_invalid_wire_bytes(v);
    return field(v);
}

/// A URL-bearing field, with `altered` counting only the replaced bytes that REACH
/// THE WIRE. Userinfo is redacted first, so a bad byte inside it is gone before the
/// scrub and is not counted. When bytes do need replacing, the conservative
/// redact_after_last_at fallback runs, and only what survives it (the text after
/// each word's last '@') is counted. Word boundaries are ASCII whitespace, which
/// scrub_wire_bytes never alters, so the words before and after scrubbing are the
/// same and the per-word count is exact.
[[nodiscard]] inline std::string url_field(std::string_view v, std::size_t& altered) {
    std::string s = redact_url_userinfo(v);
    std::size_t n = yuzu::shared::count_invalid_wire_bytes(s);
    if (n != 0) {
        n = 0;
        for (const auto w : split_apt_words(s)) {
            const std::size_t at = w.rfind('@');
            n += yuzu::shared::count_invalid_wire_bytes(at == std::string_view::npos
                                                            ? w
                                                            : w.substr(at + 1));
        }
        yuzu::shared::scrub_wire_bytes(s);
        s = redact_after_last_at(s);
    }
    altered += n;
    return field(s);
}

[[nodiscard]] inline std::string url_field(std::string_view v) {
    std::size_t ignored = 0;
    return url_field(v, ignored);
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

/// The text before the first `#` that is outside a `[...]` group. apt ends a
/// line at ANY such `#` (`main#c` is `main`; `http://h/a#b suite main` is a
/// malformed entry), not only at one preceded by whitespace.
[[nodiscard]] inline std::string_view strip_apt_comment(std::string_view line) noexcept {
    std::size_t depth = 0;
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
/// other well-formed option is tolerated and ignored. apt refuses the WHOLE list
/// for an entry it cannot read, so such an entry is malformed here (reported as
/// unparsed, never as a row apt does not use): a type other than exactly `deb` or
/// `deb-src`, an unterminated `[`, a second `[...]` block, an option without '=',
/// and too few words (a type, a uri and a suite are needed). apt de-quotes a
/// quoted option value and decodes %XX within it; this plugin does the same for
/// the three options it surfaces (see the option loop below), so neither a `%`
/// nor a `"` refuses the entry on its own.
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
        bool refused = words[0] != "deb" && words[0] != "deb-src"; // apt: "Type ... is not known"
        if (words.size() > 1 && words[1].front() == '[') {
            if (words[1].size() < 2 || words[1].back() != ']') {
                refused = true; // unterminated option block
            } else {
                options = words[1].substr(1, words[1].size() - 2);
                next = 2;
                for (const auto opt : split_apt_options(options))
                    if (opt.find('=') == std::string_view::npos)
                        refused = true; // `[trusted = yes]`, `[foo]`
            }
        }
        if (words.size() < next + 2 ||                        // type + uri + suite
            (words.size() > next && words[next].front() == '[')) // a second option block
            refused = true;
        if (refused) {
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
        for (auto opt : split_apt_options(options)) {
            const std::size_t eq = opt.find('=');
            if (eq == std::string_view::npos)
                continue; // tolerated
            std::string_view key = opt.substr(0, eq);
            const bool appends = !key.empty() && (key.back() == '+' || key.back() == '-');
            if (appends)
                key.remove_suffix(1);
            // apt de-quotes a single matching pair of double quotes around an option
            // value and decodes %XX within it (verified: [signed-by="/a b.gpg"] and
            // [lang=%65n] are both read by apt); only the three surfaced options need
            // that done here -- an ignored option's value is never looked at.
            std::string_view raw_val = opt.substr(eq + 1);
            std::string decoded_val;
            if (raw_val.size() >= 2 && raw_val.front() == '"' && raw_val.back() == '"')
                raw_val = raw_val.substr(1, raw_val.size() - 2);
            if (raw_val.find('%') != std::string_view::npos) {
                decoded_val = percent_decoded(raw_val);
                raw_val = decoded_val;
            }
            const std::string_view val = raw_val;
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
                if (!trim(line).empty())
                    ++res.malformed; // a continuation with no field to continue
                continue;            // a whitespace-only line before any field is not an entry
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

/// apt's own rule for the files of sources.list.d (verified against apt 2.0-3.2
/// with every printable ASCII byte): hidden names and any name with a character
/// outside [A-Za-z0-9_.:-] are skipped. The walk applies it BEFORE the suffix
/// test so the plugin reports the sources apt reads and no phantom ones. It is
/// NOT applied to trusted.gpg.d: apt before 3.0 trusts a key under ANY name that
/// ends in .gpg or .asc (hidden, spaces, '+', '~', non-ASCII), so filtering there
/// would hide a global trust anchor; apt 3.0 and later apply the rule there too,
/// where reporting the extra file errs on the safe side.
[[nodiscard]] inline bool apt_dir_name_ok(std::string_view name) noexcept {
    if (name.empty() || name.front() == '.')
        return false;
    for (const char c : name) {
        const bool alnum = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
        if (!alnum && c != '_' && c != '-' && c != '.' && c != ':')
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
                                                       const AptSourceFacts& f,
                                                       std::size_t* altered = nullptr) {
    std::size_t local = 0;
    std::size_t& a = altered != nullptr ? *altered : local;
    std::string out = "apt_source|";
    out += field(file, a);
    out += '|';
    out.append(apt_format_token(fmt));
    out += '|';
    out += field(f.types, a);
    out += '|';
    out += url_field(f.uris, a);
    out += '|';
    out += url_field(f.suites, a);
    out += '|';
    out += url_field(f.components, a);
    out += '|';
    out += url_field(f.signed_by, a);
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
// (an unparsed source is never silently absent). `altered`, when given, gains the
// number of bytes in the EMITTED fields that scrub_wire_bytes replaced (a NUL or
// non-UTF-8 byte in a comment or an ignored field never reaches the wire and is
// not counted).

[[nodiscard]] inline std::size_t apt_rows_from_text(std::string_view logical_file, AptFormat fmt,
                                                    std::string_view text,
                                                    std::vector<std::string>& rows,
                                                    std::size_t* altered = nullptr) {
    const AptParseResult parsed =
        fmt == AptFormat::deb822 ? parse_apt_deb822(text) : parse_apt_one_line(text);
    for (const auto& s : parsed.sources)
        rows.push_back(format_apt_source_row(logical_file, fmt, s, altered));
    return parsed.malformed;
}

} // namespace yuzu::update_source_trust
