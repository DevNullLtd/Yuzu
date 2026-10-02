/**
 * local_security_policy_parsers.hpp -- pure core of the plugin: no OS call, process
 * or clock. Every decision (errno class, status, row shape) is a function here; the
 * leg TUs only read bytes and hand them in.
 *
 * All four actions (password_policy, lockout_policy, audit_policy, sudoers) read on Linux and
 * macOS; the Windows leg serves the first three (sudoers is unsupported there). The Windows
 * leg decodes a secedit export here and returns the 2-field diagnostic row on its own faults.
 *
 * Rows (fields through safe_output_field):
 *   <action>|<key>|<value>|<source>          password_policy, lockout_policy, audit_policy
 *   sudoers|<file>|<kind>|<subject>|<runas>|<nopasswd>|<detail>   sudoers: always 7 fields
 *   <action>|status|<state>|<reason>         the zero-row fallback (local_security_policy_legs.hpp)
 *   constrained|<token>                      a contained exception (`internal_error`), or a Windows
 *                                            leg failure (local_security_policy_win.cpp)
 * A definitively missing source is the row state `absent` (key `source_state`) and no
 * failure token; an unreadable one is `unreadable:<token>` -- failure never reads as absent.
 * A pwpolicy item that is not in the documented plist shape is the same
 * `source_state|unreadable:<defect>` row plus a `pwpolicy:<defect>` token (pwpolicy_rows).
 */
#pragma once

#include <yuzu/string_utils.hpp>

#include <constraint_accumulator.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <functional>
#include <initializer_list>
#include <iterator>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::local_security_policy {

// ---- text helpers -----------------------------------------------------------

inline std::string_view trim_ws(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r'))
        s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r'))
        s.remove_suffix(1);
    return s;
}

inline std::vector<std::string_view> split_lines(std::string_view text) {
    std::vector<std::string_view> out;
    while (!text.empty()) {
        const auto nl = text.find('\n');
        out.push_back(text.substr(0, nl));
        text = nl == std::string_view::npos ? std::string_view{} : text.substr(nl + 1);
    }
    return out;
}

// ---- secedit export (UTF-16LE INI) -------------------------------------------

/// UTF-16LE with a mandatory FF FE BOM -> UTF-8. nullopt (never an empty
/// success) for a BOM-less, odd-length or unpaired-surrogate buffer.
inline std::optional<std::string> decode_utf16le_bom(std::span<const std::uint8_t> b) {
    if (b.size() < 2 || (b.size() % 2) != 0 || b[0] != 0xFF || b[1] != 0xFE) return std::nullopt;
    std::string out;
    const auto unit = [&](std::size_t i) -> std::uint32_t {
        return static_cast<std::uint32_t>(b[i]) | (static_cast<std::uint32_t>(b[i + 1]) << 8);
    };
    for (std::size_t i = 2; i < b.size(); i += 2) {
        std::uint32_t cp = unit(i);
        if (cp >= 0xDC00 && cp <= 0xDFFF) return std::nullopt;
        if (cp >= 0xD800 && cp <= 0xDBFF) {
            if (i + 3 >= b.size()) return std::nullopt;
            const std::uint32_t lo = unit(i + 2);
            if (lo < 0xDC00 || lo > 0xDFFF) return std::nullopt;
            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
            i += 2;
        }
        if (cp < 0x80) {
            out += static_cast<char>(cp);
        } else if (cp < 0x800) {
            out += static_cast<char>(0xC0 | (cp >> 6));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            out += static_cast<char>(0xE0 | (cp >> 12));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            out += static_cast<char>(0xF0 | (cp >> 18));
            out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
    }
    return out;
}

/// Case-insensitive `std::map` ordering/lookup for INI section and key names (the INF
/// rule): `secedit_export_complete` and `secedit_policy_rows` compare section/key names
/// case-insensitively; a plain `std::map<std::string,...>`
/// orders and looks up by exact bytes, so a differently-cased section or key that passed
/// the completeness check would be invisible to the row lookups -- a present setting
/// silently reading as the legitimate modal value `absent` (#4997, the defect this type
/// exists to prevent). `is_transparent` lets `.find()` take a
/// `std::string_view` literal directly. Values keep whatever casing the export file used
/// -- only lookup/ordering are case-insensitive.
struct CaseInsensitiveLess {
    using is_transparent = void;
    bool operator()(std::string_view a, std::string_view b) const {
        const std::size_t n = std::min(a.size(), b.size());
        for (std::size_t i = 0; i < n; ++i) {
            const int ca = std::tolower(static_cast<unsigned char>(a[i]));
            const int cb = std::tolower(static_cast<unsigned char>(b[i]));
            if (ca != cb) return ca < cb;
        }
        return a.size() < b.size();
    }
};

/// `[Section]` / `key = value` INI (secedit .inf). `;` comments and lines
/// before the first section are ignored; a repeated key keeps the last value
/// (case-insensitively -- see CaseInsensitiveLess -- so `MinimumPasswordLength` and a
/// later `minimumpasswordlength` in the same section are the same key). std::map, not
/// unordered: `secedit_policy_rows` iterates `[Event Audit]` directly, so the key order IS the
/// audit_policy row order on the wire.
using InfSections =
    std::map<std::string, std::map<std::string, std::string, CaseInsensitiveLess>, CaseInsensitiveLess>;

inline InfSections parse_inf_sections(std::string_view text) {
    InfSections out;
    std::map<std::string, std::string, CaseInsensitiveLess>* cur = nullptr;
    for (auto raw : split_lines(text)) {
        const auto line = trim_ws(raw);
        if (line.empty() || line.front() == ';') continue;
        if (line.front() == '[' && line.back() == ']') {
            cur = &out[std::string{trim_ws(line.substr(1, line.size() - 2))}];
            continue;
        }
        const auto eq = line.find('=');
        if (cur == nullptr || eq == std::string_view::npos) continue;
        (*cur)[std::string{trim_ws(line.substr(0, eq))}] = std::string{trim_ws(line.substr(eq + 1))};
    }
    return out;
}

// ---- key/value config files (login.defs, pwquality.conf, faillock.conf, audit_control) --

using KvList = std::vector<std::pair<std::string, std::string>>;

/// `key<sep>value` lines; `seps` is the set of separator characters (login.defs
/// " \t", pwquality/faillock " \t=", audit_control ":"). `#` lines are comments.
/// A key with no value is kept with an empty value.
inline KvList parse_kv_lines(std::string_view text, std::string_view seps) {
    KvList out;
    for (auto raw : split_lines(text)) {
        const auto line = trim_ws(raw);
        if (line.empty() || line.front() == '#') continue;
        const auto k_end = line.find_first_of(seps);
        if (k_end == std::string_view::npos) {
            out.emplace_back(std::string{line}, std::string{});
            continue;
        }
        auto rest = line.substr(k_end);
        while (!rest.empty() && (seps.find(rest.front()) != std::string_view::npos ||
                                 rest.front() == ' ' || rest.front() == '\t'))
            rest.remove_prefix(1);
        out.emplace_back(std::string{line.substr(0, k_end)}, std::string{trim_ws(rest)});
    }
    return out;
}

inline constexpr std::string_view kLoginDefsPasswordKeys[] = {
    "PASS_MAX_DAYS", "PASS_MIN_DAYS", "PASS_MIN_LEN", "PASS_WARN_AGE", "ENCRYPT_METHOD",
    "SHA_CRYPT_MIN_ROUNDS", "SHA_CRYPT_MAX_ROUNDS"};
inline constexpr std::string_view kLoginDefsLockoutKeys[] = {"LOGIN_RETRIES", "LOGIN_TIMEOUT",
                                                             "FAILLOG_ENAB", "FAIL_DELAY"};

// ---- PAM stacks -----------------------------------------------------------------

struct PamLine {
    std::string type;   // auth | account | password | session (a leading '-' dropped)
    std::string control; // required | [success=1 default=ignore] | ...
    std::string module;  // pam_unix.so
    std::string args;    // remaining text, verbatim
};

/// PAM logical lines exactly as libpam 1.7.0 assembles them (libpam_internal/pam_line.c,
/// `_pam_str_prepare`): a `#` ANYWHERE cuts the rest of the physical line and ENDS the
/// logical line, so no `\` before or inside a comment continues it; otherwise a `\`
/// ending the line (only spaces/tabs after it) joins the next physical line with one
/// blank. A blank or comment-only line ends a pending continuation.
inline std::vector<std::string> pam_logical_lines(std::string_view text) {
    std::vector<std::string> out;
    std::string cur;
    for (auto raw : split_lines(text)) {
        bool cont = false;
        if (const auto hash = raw.find('#'); hash != std::string_view::npos) {
            raw = raw.substr(0, hash);
        } else {
            while (!raw.empty() && (raw.back() == ' ' || raw.back() == '\t')) raw.remove_suffix(1);
            cont = !raw.empty() && raw.back() == '\\';
            if (cont) raw.remove_suffix(1);
        }
        raw = trim_ws(raw);
        if (!raw.empty()) {
            if (!cur.empty()) cur += ' ';
            cur.append(raw);
        }
        if (!cont && !cur.empty()) {
            out.push_back(std::move(cur));
            cur.clear();
        }
    }
    if (!cur.empty()) out.push_back(std::move(cur));
    return out;
}

/// Skips comments, blanks and `@include`. A line that is not `type control module`
/// is dropped (PAM itself would reject it) -- pam.d holds no other policy.
inline std::vector<PamLine> parse_pam_lines(std::string_view text) {
    std::vector<PamLine> out;
    for (const auto& line : pam_logical_lines(text)) {
        std::string_view s = line;
        if (s.empty() || s.front() == '@') continue;
        const auto word = [&s]() {
            s = trim_ws(s);
            const auto e = s.find_first_of(" \t");
            const auto w = s.substr(0, e);
            s = e == std::string_view::npos ? std::string_view{} : s.substr(e);
            return w;
        };
        PamLine p;
        auto t = word();
        if (!t.empty() && t.front() == '-') t.remove_prefix(1);
        p.type = std::string{t};
        s = trim_ws(s);
        if (!s.empty() && s.front() == '[') {
            const auto close = s.find(']');
            if (close == std::string_view::npos) continue;
            p.control = std::string{s.substr(0, close + 1)};
            s.remove_prefix(close + 1);
        } else {
            p.control = std::string{word()};
        }
        p.module = std::string{word()};
        p.args = std::string{trim_ws(s)};
        if (p.type.empty() || p.control.empty() || p.module.empty()) continue;
        out.push_back(std::move(p));
    }
    return out;
}

inline constexpr std::string_view kPamPasswordModules[] = {"pam_pwquality.so", "pam_pwhistory.so",
                                                            "pam_cracklib.so", "pam_unix.so"};
inline constexpr std::string_view kPamLockoutModules[] = {"pam_faillock.so", "pam_tally2.so",
                                                           "pam_tally.so"};

// ---- auditd rules -----------------------------------------------------------------

struct AuditRuleCounts {
    std::size_t total = 0;    // every non-comment, non-blank line
    std::size_t watches = 0;  // -w
    std::size_t syscalls = 0; // -a / -A
    std::size_t control = 0;  // -D/-b/-f/-r/-i/-c/-e/--backlog_wait_time/--loginuid-immutable
    std::size_t unmodelled = 0;
    std::optional<std::string> enabled; // -e value, last one wins

    /// The RULE count. A control directive (-D, -b, -f, -e, ...) configures the
    /// auditd subsystem; it is not a rule, and counting it as one reports
    /// "4 rules" for a stock file that contains no rule at all. An unrecognised
    /// line counts as a rule: this is a rules file, and over-reporting an
    /// unknown line is safer than dropping a real rule.
    [[nodiscard]] std::size_t rules() const { return watches + syscalls + unmodelled; }
};

inline AuditRuleCounts parse_auditd_rules_count(std::string_view text) {
    AuditRuleCounts c;
    for (auto raw : split_lines(text)) {
        const auto line = trim_ws(raw);
        if (line.empty() || line.front() == '#') continue;
        ++c.total;
        const auto sp = line.find_first_of(" \t");
        const auto opt = line.substr(0, sp);
        if (opt == "-w") ++c.watches;
        else if (opt == "-a" || opt == "-A") ++c.syscalls;
        else if (opt == "-e") {
            c.enabled = std::string{sp == std::string_view::npos ? "" : trim_ws(line.substr(sp))};
            ++c.control;
        }
        else if (opt == "-D" || opt == "-b" || opt == "-f" || opt == "-r" || opt == "-i" ||
                 opt == "-c" || opt == "--backlog_wait_time" || opt == "--loginuid-immutable")
            ++c.control; // configures auditd; not a rule
        else ++c.unmodelled;
    }
    return c;
}

/// auditctl -e: 0 disabled, 1 enabled, 2 immutable; anything else is the named `unmodelled:`.
inline std::string audit_enabled_token(std::string_view v) {
    if (v == "0") return "disabled";
    if (v == "1") return "enabled";
    if (v == "2") return "immutable";
    return "unmodelled:" + std::string{v}; // escaped once, by the row formatter
}

// ---- sudoers ------------------------------------------------------------------------

struct SudoersEntry {
    std::string kind, subject, runas, nopasswd, commands;
};

namespace detail {

/// One sudoers token over SudoersStatement::text[b, e). `kind` is the character itself
/// for `( ) , = : ! >`, else 'w' a word (name, alias, keyword, %group, +netgroup, #uid,
/// IP address), 's' a double-quoted string, 'c' a command (a path, regex or sudoedit with
/// its arguments), 't' a tag with its colon, 'd' a digest spec, 'x' text sudo rejects.
struct SudoersToken {
    char kind;
    std::size_t b, e;
};

/// One statement: comments cut, each line continuation replaced by one blank (by nothing
/// inside a quoted string, as sudo joins it) and every other blank run by one blank.
struct SudoersStatement {
    std::string text;
    std::vector<SudoersToken> toks;
};

inline constexpr std::string_view kSudoersTags[] = {
    "NOPASSWD", "PASSWD", "NOEXEC", "EXEC", "INTERCEPT", "NOINTERCEPT", "SETENV", "NOSETENV",
    "LOG_OUTPUT", "NOLOG_OUTPUT", "LOG_INPUT", "NOLOG_INPUT", "MAIL", "NOMAIL", "FOLLOW",
    "NOFOLLOW"};
inline constexpr std::string_view kSudoersOptions[] = {
    "CWD", "CHROOT", "TIMEOUT", "NOTBEFORE", "NOTAFTER", "ROLE", "TYPE", "APPARMOR_PROFILE",
    "PRIVS", "LIMITPRIVS"};

/// sudoers(5) lexing in ONE linear pass, following sudo 1.9.16's toke.l rather than
/// approximating it -- each ad-hoc scan it replaces reported a passwordless grant as
/// `nopasswd=false` for some legal line. The rules that decide a statement's shape:
///  - `#` starts a comment unless followed by a digit (`#1000`, a uid) or inside double
///    quotes, glued to a token or not (`/bin/ls#note` is `/bin/ls` then a comment). A
///    comment runs to the end of the physical line and ENDS the statement: a `\` before
///    or inside it never continues onto the next line. `#include` is a directive only in
///    column 0.
///  - `\`, optional blanks, newline continues the statement, except glued to a word as
///    `\ ` (an escaped blank, as sudo's WORD) -- and `\ # x` is an escaped blank, then a
///    comment, so it does not continue either.
///  - A command (`/path`, `^regex$`, `sudoedit`) takes arguments up to an unescaped
///    `#`, `:`, `,` or `=`; a double quote there is literal. Elsewhere `"..."` is one
///    token (`CWD="/x y:z"`) with `\"` inside it, and `\` escapes the next character.
///  - `NAME:` with a tag name (blanks allowed before the colon) is one tag token, a
///    `sha224`..`sha512` digest with its colon and digest is one token, and an IPv6
///    literal (`2001:db8::1`, `::1`) is one word -- so no colon inside any of them is
///    ever a separator.
class SudoersLexer {
public:
    explicit SudoersLexer(std::string_view src) : s_{src} {}

    std::vector<SudoersStatement> run() {
        while (i_ < s_.size()) step();
        end_statement();
        return std::move(out_);
    }

private:
    std::string_view s_;
    std::size_t i_ = 0, bol_ = 0;
    SudoersStatement st_;
    std::vector<SudoersStatement> out_;
    bool blank_ = false, defaults_ = false, want_value_ = false, bad_ = false;
    static constexpr std::size_t npos = std::string_view::npos;

    static bool digit(char c) { return c >= '0' && c <= '9'; }
    static bool xdigit(char c) { return std::isxdigit(static_cast<unsigned char>(c)) != 0; }
    [[nodiscard]] char at(std::size_t k) const { return k < s_.size() ? s_[k] : '\0'; }
    [[nodiscard]] std::size_t newline_len(std::size_t k) const {
        return at(k) == '\n' ? 1 : (at(k) == '\r' && at(k + 1) == '\n' ? 2 : 0);
    }
    /// Index just past a line continuation (`\`, blanks, newline) starting at k, or 0.
    [[nodiscard]] std::size_t continuation(std::size_t k) const {
        if (at(k) != '\\') return 0;
        for (++k; at(k) == ' ' || at(k) == '\t'; ++k) {}
        const std::size_t nl = newline_len(k);
        return nl != 0 ? k + nl : 0;
    }
    std::size_t mark() {
        if (blank_ && !st_.text.empty()) st_.text += ' ';
        blank_ = false;
        return st_.text.size();
    }
    void put(char c) {
        mark();
        st_.text += c;
    }
    void emit(char kind, std::size_t b) { st_.toks.push_back({kind, b, st_.text.size()}); }
    void end_statement() {
        if (!st_.text.empty()) out_.push_back(std::move(st_));
        st_ = {};
        blank_ = defaults_ = want_value_ = false;
    }

    void step() {
        const char c = s_[i_];
        if (const std::size_t nl = newline_len(i_)) {
            i_ = bol_ = i_ + nl;
            return end_statement();
        }
        if (c == ' ' || c == '\t' || c == '\r') {
            blank_ = true;
            ++i_;
            return;
        }
        if (const std::size_t next = continuation(i_)) {
            blank_ = true;
            i_ = bol_ = next;
            return;
        }
        const bool uid = digit(at(i_ + 1)) || (at(i_ + 1) == '-' && digit(at(i_ + 2)));
        if (c == '#' && !uid) {
            if (i_ == bol_ && st_.toks.empty() && include_directive()) return;
            while (i_ < s_.size() && newline_len(i_) == 0) ++i_; // a comment
            return;
        }
        const std::size_t b = mark();
        if (c == '"') return quoted(b);
        if (!defaults_ && !want_value_ && (c == '/' || c == '^')) return command(b);
        if (const std::size_t n = ipv6_len()) {
            copy(n);
            want_value_ = false;
            return emit('w', b);
        }
        if (c == '!') {
            std::size_t n = 0;
            for (; at(i_) == '!'; ++n) copy(1);
            if (n % 2 == 1) emit('!', b); // an even run cancels out, as in sudo
            return;
        }
        if (std::string_view{"(),=:>"}.find(c) != npos) {
            copy(1);
            return emit(c, b);
        }
        for (const auto name : kSudoersTags) {
            if (!s_.substr(i_).starts_with(name)) continue;
            std::size_t k = i_ + name.size();
            while (at(k) == ' ' || at(k) == '\t') ++k;
            if (at(k) != ':') continue;
            st_.text.append(name);
            st_.text += ':';
            i_ = k + 1;
            return emit('t', b);
        }
        word(b);
    }

    void copy(std::size_t n) {
        for (std::size_t k = 0; k < n; ++k) put(s_[i_ + k]);
        i_ += n;
    }

    bool include_directive() {
        for (const std::string_view d : {"#includedir", "#include"}) {
            const char after = at(i_ + d.size());
            if (!s_.substr(i_).starts_with(d) || (after != ' ' && after != '\t')) continue;
            const std::size_t b = mark();
            copy(d.size());
            emit('w', b);
            include_path();
            return true;
        }
        return false;
    }

    /// The path after an include directive (toke.l GOTINC): quoted, or non-space text.
    void include_path() {
        while (at(i_) == ' ' || at(i_) == '\t') {
            blank_ = true;
            ++i_;
        }
        const std::size_t b = mark();
        if (at(i_) == '"') return quoted(b);
        while (i_ < s_.size() && std::isspace(static_cast<unsigned char>(s_[i_])) == 0)
            copy(s_[i_] == '\\' && (at(i_ + 1) == ' ' || at(i_ + 1) == '\t') ? 2 : 1);
        if (st_.text.size() > b) emit('w', b);
    }

    void quoted(std::size_t b) {
        copy(1);
        for (;;) {
            if (i_ >= s_.size() || newline_len(i_) != 0) return emit('x', b); // unterminated
            if (const std::size_t next = continuation(i_)) {
                for (i_ = bol_ = next; at(i_) == ' ' || at(i_) == '\t';) ++i_;
                continue;
            }
            const char ch = s_[i_];
            copy(ch == '\\' && at(i_ + 1) == '"' ? 2 : 1);
            if (ch == '"') break;
        }
        want_value_ = false;
        emit('s', b);
    }

    /// Length of an IPv6 literal at i_ (toke.l IPV6ADDR, with an optional /prefix), or 0.
    [[nodiscard]] std::size_t ipv6_len() const {
        const auto hex = [this](std::size_t k) {
            std::size_t n = 0;
            while (n < 4 && xdigit(at(k + n))) ++n;
            return n;
        };
        std::size_t k = i_, groups = 0;
        for (; groups < 7 && at(k + hex(k)) == ':'; ++groups) k += hex(k) + 1;
        if (groups < 2) return 0;
        k += hex(k);
        while (digit(at(k)) || at(k) == '.') ++k; // an embedded IPv4 tail
        if (at(k) == '/')
            for (++k; xdigit(at(k)) || at(k) == ':' || at(k) == '.';) ++k;
        return k - i_;
    }

    void word(std::size_t b) {
        if (at(i_) == '%') copy(at(i_ + 1) == ':' ? 2 : 1);
        if (at(i_) == '#') { // #uid, %#gid
            copy(at(i_ + 1) == '-' ? 2 : 1);
            while (digit(at(i_))) copy(1);
        } else {
            while (i_ < s_.size()) {
                const char ch = s_[i_];
                if (ch == '\\') {
                    const char n = at(i_ + 1);
                    if (i_ + 1 >= s_.size() || n == '\n' || n == '\r' || (n == '\t' && !defaults_))
                        break;
                    copy(2);
                } else if (std::string_view{"#>!=:,() \t\r\n\""}.find(ch) == npos) {
                    copy(1);
                } else {
                    break;
                }
            }
        }
        if (st_.text.size() == b) { // nothing sudo lexes starts here
            copy(1);
            return emit('x', b);
        }
        const std::string w = st_.text.substr(b);
        if (w == "sudoedit" && !defaults_ && !want_value_) return command_args(b);
        if (w == "sha224" || w == "sha256" || w == "sha384" || w == "sha512") {
            std::size_t k = i_;
            while (at(k) == ' ' || at(k) == '\t') ++k;
            std::size_t d = k + 1;
            while (at(d) == ' ' || at(d) == '\t') ++d;
            const std::size_t d0 = d;
            const auto digest_char = [](char ch) {
                return std::isalnum(static_cast<unsigned char>(ch)) != 0 || ch == '+' || ch == '/' ||
                       ch == '=';
            };
            while (digest_char(at(d))) ++d;
            if (at(k) == ':' && d > d0) {
                st_.text += ':';
                i_ = d0;
                copy(d - d0);
                return emit('d', b);
            }
        }
        if (st_.toks.empty() && w.starts_with("Defaults") && (w.size() == 8 || w[8] == '@'))
            defaults_ = true;
        emit('w', b);
        if (w == "@include" || w == "@includedir") include_path();
        want_value_ = w == "CWD" || w == "CHROOT"; // toke.l EXPECTPATH: the value is no command
    }

    void command(std::size_t b) {
        if (s_[i_] == '/') {
            while (i_ < s_.size()) {
                const char ch = s_[i_];
                if (ch == '\\' && i_ + 1 < s_.size() &&
                    std::string_view{",:= \t#"}.find(s_[i_ + 1]) != npos)
                    copy(2);
                else if (std::string_view{",:=\\ \t\r\n#"}.find(ch) == npos)
                    copy(1);
                else
                    break;
            }
            if (st_.text.back() == '/') return emit('c', b); // a directory takes no arguments
            return command_args(b);
        }
        // toke.l REGEX is the LONGEST match: it ends at the last `$` before an unescaped
        // `#`, an unescaped `$` or the line end.
        std::size_t end = 0, k = i_ + 1;
        for (; k < s_.size() && newline_len(k) == 0; ++k) {
            const bool escaped = s_[k - 1] == '\\';
            if (s_[k] == '#' && !escaped) break;
            if (s_[k] == '$') {
                end = k + 1;
                if (!escaped) break;
            }
        }
        if (end == 0) { // unterminated: consumed whole, so no later `^` rescans it
            copy(k - i_);
            return emit('x', b);
        }
        copy(end - i_);
        command_args(b);
    }

    /// toke.l GOTCMND: arguments run to an unescaped `#`, `:`, `,` or the line end. `=` is
    /// an ordinary argument character here (env assignments, `--flag=value`) -- it is NOT
    /// in this break set, unlike command()'s own PATH-name scan just above, where `=` DOES
    /// end the token per toke.l's PATH rule and must stay excluded there. Including it here
    /// too used to cut a legal `NOPASSWD: /usr/bin/rsync --rsync-path=x` at the `=`,
    /// misreporting it `unmodelled` (#4997; loud via the undecoded_passwd_tag fail-safe,
    /// since the raw NOPASSWD: text survives -- not silent, but still wrong).
    void command_args(std::size_t b) {
        bad_ = false;
        bool have_arg = false;
        while (i_ < s_.size() && newline_len(i_) == 0) {
            const char ch = s_[i_];
            if (std::string_view{"#:,"}.find(ch) != npos) break;
            if (ch == ' ' || ch == '\t' || ch == '\r') {
                blank_ = true;
                ++i_;
            } else if (const std::size_t next = continuation(i_)) {
                blank_ = true;
                i_ = bol_ = next;
            } else if (ch == '^' && !have_arg) {
                arg_regex();
                break;
            } else if (ch == '\\') {
                const bool known = i_ + 1 < s_.size() &&
                    std::string_view{":\\,= \t#*?[]!^"}.find(s_[i_ + 1]) != npos;
                bad_ = bad_ || !known;
                copy(known ? 2 : 1);
                have_arg = true;
            } else {
                copy(1);
                have_arg = true;
            }
        }
        emit(bad_ ? 'x' : 'c', b);
    }

    /// toke.l GOTREGEX: a first argument `^...$` may hold blanks, commas and colons; it
    /// ends the command. `#` or a line end inside it is an error.
    void arg_regex() {
        copy(1);
        while (i_ < s_.size() && newline_len(i_) == 0 && s_[i_] != '#') {
            if (const std::size_t next = continuation(i_)) {
                i_ = bol_ = next;
                continue;
            }
            const char ch = s_[i_];
            copy(ch == '\\' && i_ + 1 < s_.size() && newline_len(i_ + 1) == 0 ? 2 : 1);
            if (ch == '$') return;
        }
        bad_ = true;
    }
};

/// True when `s` still carries an unescaped `NOPASSWD:` / `PASSWD:` tag (blanks
/// allowed before the colon). A decoded tag is removed from the row's text, so
/// one found here was NOT decoded into the `nopasswd` column.
inline bool has_passwd_tag(std::string_view s) {
    for (std::size_t at = 0; (at = s.find("PASSWD", at)) != std::string_view::npos; ++at) {
        const std::size_t b = at >= 2 && s.substr(at - 2, 2) == "NO" ? at - 2 : at;
        if (b > 0 && (std::isalnum(static_cast<unsigned char>(s[b - 1])) || s[b - 1] == '_'))
            continue;
        std::size_t e = at + 6;
        while (e < s.size() && (s[e] == ' ' || s[e] == '\t')) ++e;
        if (e < s.size() && s[e] == ':') return true;
    }
    return false;
}

/// Output bounds for one user spec. Every clause repeats the User_List in its subject
/// and every run-as/NOPASSWD flip repeats both, so a single grammar-legal 256 KiB line
/// could otherwise expand into gigabytes of rows. A User_List, Host_List or run-as longer
/// than kMaxSudoersListBytes, or a line yielding more than kMaxSudoersLineEntries
/// entries, is not decoded: the caller reports the line once as `unmodelled` with its
/// raw text, and a NOPASSWD:/PASSWD: tag in it still trips the undecoded_passwd_tag
/// failure. Together with parse_sudoers' per-file entry cap, output per file stays
/// bounded by (entries x ~12 KiB), not by the line's repetition structure.
inline constexpr std::size_t kMaxSudoersListBytes = 4096;
inline constexpr std::size_t kMaxSudoersLineEntries = 256;
// The point of the bound is that it is SMALL (a pre-fix value of 4096 amplified one line into
// hundreds of MiB): pin the ceiling so a later edit cannot quietly raise it.
static_assert(kMaxSudoersListBytes <= 4096 && kMaxSudoersLineEntries <= 256);

/// One lexed user spec, parsed by the sudoers(5) grammar:
/// `User_List Host_List = Cmnd_Spec_List (: Host_List = Cmnd_Spec_List)*`, each
/// Cmnd_Spec `[(Runas)] Option_Spec* Tag_Spec* Digest_Spec* !* Cmnd`. One entry per
/// contiguous (runas, NOPASSWD) run of each Host_List clause; runas and tags carry
/// across one clause's Cmnd_Specs, never into the next clause. Every tag other than
/// NOPASSWD:/PASSWD: is kept in the command text as `TAG: `, every Option_Spec verbatim.
/// nullopt when the tokens do not follow the grammar.
///
/// WHAT `nopasswd` GUARANTEES: the clause colon is a token, so a `:` inside a quoted
/// Option_Spec value, an IPv6 host, a digest, a runas group or an escape never splits a
/// clause. Defence in depth: a NOPASSWD:/PASSWD: tag that still survives into any field
/// makes the whole line nullopt -- parse_sudoers reports it `unmodelled` and the collector
/// adds `<file>:undecoded_passwd_tag` (CONSTRAINED). Known limits: this is sudo 1.9.16's
/// lexing (checked against it differentially); the column is the tag alone (a Defaults
/// `!authenticate` also removes the password prompt); aliases and includes are not
/// resolved; and a line sudo itself rejects is reported best-effort.
inline std::optional<std::vector<SudoersEntry>> parse_user_spec(const SudoersStatement& st) {
    const auto& t = st.toks;
    const std::string_view text = st.text;
    std::size_t k = 0;
    const auto is = [&](char kind) { return k < t.size() && t[k].kind == kind; };
    const auto span = [&](std::size_t b, std::size_t e) {
        return std::string{text.substr(b, e - b)};
    };
    // User_List / Host_List: item (',' item)*, item = '!'* word-or-string; verbatim text.
    const auto member_list = [&]() -> std::optional<std::string> {
        const std::size_t first = k;
        for (;;) {
            while (is('!')) ++k;
            if (!is('w') && !is('s')) return std::nullopt;
            ++k;
            if (!is(',')) return span(t[first].b, t[k - 1].e);
            ++k;
        }
    };
    const auto users = member_list();
    if (!users || users->size() > kMaxSudoersListBytes) return std::nullopt;
    std::vector<SudoersEntry> out;
    for (;;) {
        const auto host = member_list();
        if (!host || !is('=') || host->size() > kMaxSudoersListBytes ||
            out.size() >= kMaxSudoersLineEntries)
            return std::nullopt;
        ++k;
        const std::string subject = *users + "@" + *host;
        std::string runas = "-", nopasswd = "false";
        std::vector<std::string> run;
        bool overflow = false;
        const auto flush = [&] {
            if (run.empty()) return;
            if (out.size() >= kMaxSudoersLineEntries) { // every flip repeats subject + runas
                overflow = true;
                run.clear();
                return;
            }
            std::string cmds;
            for (const auto& c : run) cmds += (cmds.empty() ? "" : ", ") + c;
            out.push_back({"user_spec", subject, runas, nopasswd, std::move(cmds)});
            run.clear();
        };
        for (;;) {
            std::string next_runas = runas, next_nopw = nopasswd, kept;
            if (is('(')) {
                const std::size_t open = k++;
                while (is('w') || is('s') || is(',') || is(':') || is('!')) ++k;
                if (!is(')')) return std::nullopt;
                next_runas = std::string{trim_ws(text.substr(t[open].e, t[k].b - t[open].e))};
                if (next_runas.size() > kMaxSudoersListBytes) return std::nullopt;
                ++k;
            }
            for (;;) { // Option_Spec and Tag_Spec, accepted in any order
                if (is('t')) {
                    const auto name = text.substr(t[k].b, t[k].e - t[k].b - 1);
                    if (name == "NOPASSWD") next_nopw = "true";
                    else if (name == "PASSWD") next_nopw = "false";
                    else kept.append(name).append(": ");
                    ++k;
                } else if (is('w') && k + 2 < t.size() && t[k + 1].kind == '=' &&
                           (t[k + 2].kind == 'w' || t[k + 2].kind == 's') &&
                           std::ranges::find(kSudoersOptions, text.substr(t[k].b, t[k].e - t[k].b)) !=
                               std::end(kSudoersOptions)) {
                    kept.append(span(t[k].b, t[k + 2].e)).append(" ");
                    k += 3;
                } else {
                    break;
                }
            }
            const std::size_t cmd_b = k < t.size() ? t[k].b : text.size();
            while (is('d')) {
                ++k;
                if (is(',') && k + 1 < t.size() && t[k + 1].kind == 'd') ++k;
            }
            while (is('!')) ++k;
            if (!is('c') && !is('w')) return std::nullopt;
            const std::size_t cmd_e = t[k++].e;
            if (next_runas != runas || next_nopw != nopasswd) flush();
            runas = std::move(next_runas);
            nopasswd = std::move(next_nopw);
            run.push_back(kept + span(cmd_b, cmd_e));
            if (!is(',')) break;
            ++k;
        }
        flush();
        if (overflow) return std::nullopt;
        if (k == t.size()) break;
        if (!is(':')) return std::nullopt;
        ++k;
    }
    for (const auto& e : out)
        if (has_passwd_tag(e.subject) || has_passwd_tag(e.runas) || has_passwd_tag(e.commands))
            return std::nullopt;
    return out;
}

} // namespace detail

/// Parses one sudoers file. `#include`/`#includedir`/`@include*` are listed
/// (kind include/includedir), never followed; any other statement that is not a
/// Defaults / *_Alias / user spec is kind `unmodelled` with the statement text in
/// `commands` -- never dropped. An `unmodelled` line that still carries a
/// NOPASSWD:/PASSWD: tag is the collector's `undecoded_passwd_tag` failure.
inline std::vector<SudoersEntry> parse_sudoers(std::string_view text,
                                               std::size_t max_entries = static_cast<std::size_t>(-1)) {
    std::vector<SudoersEntry> out;
    for (const auto& st : detail::SudoersLexer{text}.run()) {
        if (out.size() >= max_entries) break; // the caller's row budget: stop parsing once it is met
                                              // (one statement may overshoot by < kMaxSudoersLineEntries)
        const std::string_view line = st.text;
        auto word = line.substr(0, line.find_first_of(" \t"));
        // A Defaults scope is a list, and the grammar allows blanks around its commas
        // (`Defaults:alice, bob !authenticate`): extend the scope word over them, or `bob`
        // would land in the commands column and drop out of the subject.
        if (word.substr(0, 8) == "Defaults" && word.size() > 8) {
            std::size_t end = word.size();
            for (;;) {
                std::size_t p = end;
                while (p < line.size() && (line[p] == ' ' || line[p] == '\t')) ++p;
                const bool comma_before = end > 0 && line[end - 1] == ',';
                if (!comma_before && !(p < line.size() && line[p] == ',')) break;
                if (p < line.size() && line[p] == ',') ++p;
                while (p < line.size() && (line[p] == ' ' || line[p] == '\t')) ++p;
                const std::size_t q = std::min(line.find_first_of(" \t", p), line.size());
                if (q == p) break;
                end = q;
            }
            word = line.substr(0, end);
        }
        const auto rest = trim_ws(line.substr(word.size()));
        if (word == "#include" || word == "@include")
            out.push_back({"include", "-", "-", "-", std::string{rest}});
        else if (word == "#includedir" || word == "@includedir")
            out.push_back({"includedir", "-", "-", "-", std::string{rest}});
        else if (word.substr(0, 8) == "Defaults" &&
                 (word.size() == 8 || std::string_view{":@!>"}.find(word[8]) != std::string_view::npos)) {
            std::string scope = "-"; // Defaults:user / @host / !cmnd / >runas
            if (word.size() > 8) {
                const auto k = std::string_view{":@!>"}.find(word[8]);
                scope = std::string{std::array{"user:", "host:", "cmnd:", "runas:"}[k]} + std::string{word.substr(9)};
            }
            out.push_back({"defaults", scope, "-", "-", std::string{rest}});
        } else if (
            // `Cmd_Alias` is a sudo-legal synonym for `Cmnd_Alias` (toke.l's alias rule
            // matches `(Host|Cmnd|Cmd|User|Runas)_Alias`) -- omitting it let a line like
            // `Cmd_Alias SHELLS = /bin/sh` fall through to parse_user_spec below and
            // silently invent a user_spec row for a fictitious principal "Cmd_Alias" on
            // host "SHELLS", under a clean OK/FULL result with no failure token (#4997).
            word == "User_Alias" || word == "Runas_Alias" || word == "Host_Alias" ||
            word == "Cmnd_Alias" || word == "Cmd_Alias") {
            const auto eq = rest.find('=');
            out.push_back({"alias", std::string{word} + ":" + std::string{trim_ws(rest.substr(0, eq))},
                           "-", "-", eq == std::string_view::npos ? "" : std::string{trim_ws(rest.substr(eq + 1))}});
        } else if (auto spec = detail::parse_user_spec(st)) {
            for (auto& e : *spec) out.push_back(std::move(e));
        } else {
            out.push_back({"unmodelled", "-", "-", "-", std::string{line}});
        }
    }
    return out;
}

/// sudo skips /etc/sudoers.d names containing '.' or ending in '~'.
inline bool sudoers_dir_entry_ignored(std::string_view name) {
    return name.find('.') != std::string_view::npos || (!name.empty() && name.back() == '~');
}

// ---- errno classification and status (one function for every leg) --------------------

inline constexpr int kReadOversized = -1;
inline constexpr int kReadNotRegular = -2;
/// The file holds a NUL byte. Every C consumer of these files (sudo's lexer, libpam,
/// shadow's getdef) stops or diverges at it, so no value read past it can be reported
/// as the one in force, and a NUL crossing write_output's C string would cut the row.
inline constexpr int kReadEmbeddedNul = -3;
/// A sudoers source is a symlink. The sudoers reader opens O_NOFOLLOW: the action returns
/// file CONTENT (unparsable lines verbatim), so a planted link would turn it into a read
/// primitive for any file the agent can read. Never followed, never treated as absent.
inline constexpr int kReadSymlink = -4;
/// A sudoers source is not owned by uid 0 or is group/other-writable. Stricter than sudo's own
/// check (sudo allows a group-writable file owned by the sudoers group), and the same direction:
/// content sudo would refuse is never reported as policy.
inline constexpr int kReadInsecure = -5;

/// The owner a sudoers source must have in production: root. Named so the default cannot drift
/// (the reader takes the owner as a parameter only so tests can run as any user).
inline constexpr unsigned kSudoersOwnerUid = 0;
static_assert(kSudoersOwnerUid == 0, "sudoers sources must be root-owned");

/// The sources read under the strict (no-follow, root-owned) rule. Every other source keeps
/// the following reader: /etc/pam.d/system-auth is a real symlink into /etc/authselect.
inline bool is_sudoers_source(std::string_view path) {
    return path == "/etc/sudoers" || path.starts_with("/etc/sudoers.d/");
}

enum class ReadClass { Absent, Denied, Failed };
struct ReadOutcome {
    ReadClass cls;
    std::string token; // lower_snake failure token; empty for Absent
};

inline ReadOutcome classify_read_errno(int err) {
    switch (err) {
    case ENOENT:
    case ENOTDIR: return {ReadClass::Absent, ""};
    case EACCES:
    case EPERM: return {ReadClass::Denied, "permission_denied"};
    case ELOOP: return {ReadClass::Failed, "symlink_loop"};
    case EIO: return {ReadClass::Failed, "io_error"};
    case kReadOversized: return {ReadClass::Failed, "oversized"};
    case kReadNotRegular: return {ReadClass::Failed, "not_regular"};
    case kReadEmbeddedNul: return {ReadClass::Failed, "embedded_nul"};
    case kReadSymlink: return {ReadClass::Failed, "symlink_refused"};
    case kReadInsecure: return {ReadClass::Failed, "insecure_owner_or_mode"};
    default: return {ReadClass::Failed, "errno_" + std::to_string(err)};
    }
}

enum class PolicyStatus { Ok, Constrained, PermissionDenied };

/// PERMISSION_DENIED only when every existing source was refused (nothing
/// readable, nothing else failed); any other failure is CONSTRAINED; else OK.
inline PolicyStatus select_status(std::size_t readable, std::size_t denied, std::size_t failed) {
    if (denied == 0 && failed == 0) return PolicyStatus::Ok;
    if (readable == 0 && failed == 0) return PolicyStatus::PermissionDenied;
    return PolicyStatus::Constrained;
}

// ---- row formatters ---------------------------------------------------------------------

/// A NUL never reaches write_output, which takes a C string and would silently end the
/// row there. Every source already refuses one upstream (kReadEmbeddedNul, cf_to_utf8,
/// secedit:embedded_nul), so this substitution (U+FFFD, visible) is defence in depth.
///
/// Every field goes through sanitize_utf8 before safe_output_field -- same order as
/// runtimes_parsers.hpp's field formatter. This is the ONE call site every row in this
/// plugin passes through (format_kv_row has no other caller), so it is also the single
/// chokepoint closing two independent invalid-byte paths at once: raw /etc file content
/// (login.defs/pwquality.conf/faillock.conf/audit.rules values, PAM control/args) is never
/// scrubbed before reaching a row, and a byte-offset truncation elsewhere in this file
/// (pwpolicy_rows' identifier cut) could otherwise leave a severed multibyte sequence at
/// the end of a field (fjarvis review finding, PR #5069).
inline std::string join_row(std::string_view head, std::initializer_list<std::string_view> fields) {
    std::string r{head};
    for (auto f : fields) {
        r += '|';
        r += yuzu::util::safe_output_field(yuzu::util::sanitize_utf8(std::string{f}));
    }
    for (std::size_t at = 0; (at = r.find('\0', at)) != std::string::npos;)
        r.replace(at, 1, "\xEF\xBF\xBD");
    return r;
}

/// A key present with no value reads `present`.
inline std::string format_kv_row(std::string_view action, std::string_view key,
                                 std::string_view value, std::string_view source) {
    return join_row(action, {key, value.empty() ? std::string_view{"present"} : value, source});
}

inline std::string format_sudoers_row(std::string_view file, const SudoersEntry& e) {
    return join_row("sudoers", {file, e.kind, e.subject, e.runas, e.nopasswd, e.commands});
}

// ---- file-source collector (Linux and macOS file legs; reader injected) --------------------

struct FileRead {
    int err = 0; // 0 = ok; errno, or a kRead* code above
    std::string data;
};
struct DirList {
    int err = 0;
    std::vector<std::string> names; // sorted, no "." / ".."
    bool truncated = false;
};
using FileReader = std::function<FileRead(const std::string&)>;
using DirLister = std::function<DirList(const std::string&)>;

enum class LocalPolicyAction { Password, Lockout, Audit, Sudoers, Unknown };
enum class FileFlavor { Linux, Macos };

inline LocalPolicyAction parse_local_policy_action(std::string_view a) {
    if (a == "password_policy") return LocalPolicyAction::Password;
    if (a == "lockout_policy") return LocalPolicyAction::Lockout;
    if (a == "audit_policy") return LocalPolicyAction::Audit;
    if (a == "sudoers") return LocalPolicyAction::Sudoers;
    return LocalPolicyAction::Unknown;
}
/// Exhaustive rather than defaulted: a `default:` arm here mapped Unknown to
/// "sudoers", silently labelling rows with a prefix whose contract is 7 fields,
/// not 4. Unreachable today (execute() rejects Unknown before any leg runs), but
/// the compiler now enforces that a new action gets a deliberate answer.
inline std::string_view action_row_prefix(LocalPolicyAction a) {
    switch (a) {
    case LocalPolicyAction::Password: return "password_policy";
    case LocalPolicyAction::Lockout: return "lockout_policy";
    case LocalPolicyAction::Audit: return "audit_policy";
    case LocalPolicyAction::Sudoers: return "sudoers";
    case LocalPolicyAction::Unknown: break;
    }
    return "";
}

inline constexpr std::size_t kMaxFileBytes = 256 * 1024;
inline constexpr std::size_t kMaxDirEntries = 256;
inline constexpr std::size_t kMaxRows = 4096;
inline constexpr std::size_t kMaxRowBytes = 4u * 1024 * 1024; // formatted output cap per dispatch

struct Collected {
    std::vector<std::string> rows;
    PolicyStatus status = PolicyStatus::Ok;
    std::string reason; // comma-joined `<source>:<token>` failure tokens
};

namespace detail {

struct Tally {
    std::size_t readable = 0, denied = 0, failed = 0;
    yuzu::shared::ConstraintAccumulator acc;
    std::vector<std::string> rows;
    bool capped = false;

    /// The LAST slot is reserved for the truncation marker itself. Without that
    /// reservation the cap silently drops the row announcing the cap, so the
    /// output ended on an ordinary row indistinguishable from a complete dump --
    /// the one place a non-OK status was not paired with a row saying why.
    /// `marker_prefix` is the action's row prefix; `marker_fields` makes the
    /// marker match the action's own field count (4 for the kv actions, 7 for
    /// sudoers), so the truncation notice never breaks the wire shape.
    void row(std::string r) {
        // Row COUNT alone does not bound output: sudoers rows can each be ~12 KiB, so 4096 of them
        // is ~50 MB from a 256 KiB file. The byte budget shares the row cap's marker and status.
        if (rows.size() + 1 >= kMaxRows || bytes + r.size() > kMaxRowBytes) {
            if (!capped) {
                acc.add_failure("row_cap");
                rows.push_back(truncation_marker());
            }
            capped = true;
            return;
        }
        bytes += r.size() + 1;
        rows.push_back(std::move(r));
    }

    std::size_t bytes = 0; // formatted row bytes so far (each row plus its newline)
    std::string marker_prefix{"local_security_policy"};
    std::size_t marker_fields{4};
    [[nodiscard]] std::string truncation_marker() const {
        return marker_fields == 7
                   ? format_sudoers_row("-", {"unreadable", "-", "-", "-", "row_cap"})
                   : format_kv_row(marker_prefix, "source_state", "unreadable:row_cap",
                                   marker_prefix);
    }
    /// Records a failed (non-absent) read.
    void failure(const ReadOutcome& o, std::string_view src) {
        (o.cls == ReadClass::Denied ? denied : failed)++;
        acc.add_failure(std::string{src} + ":" + o.token);
    }
    /// Records the outcome and returns {state, detail}: {"absent", ""} or {"unreadable", token}.
    std::pair<std::string, std::string> state_of(const ReadOutcome& o, std::string_view src) {
        if (o.cls == ReadClass::Absent) return {"absent", ""};
        failure(o, src);
        return {"unreadable", o.token};
    }
};

inline std::string kv_state_text(const std::pair<std::string, std::string>& st) {
    return st.second.empty() ? st.first : st.first + ":" + st.second;
}

/// The one call site of the injected reader: a read that succeeded but holds a NUL
/// byte is the failure kReadEmbeddedNul (the whole source `unreadable:embedded_nul`
/// plus a token -- the same convention as oversized or not_regular), never a value.
inline FileRead checked_read(const FileReader& rd, const std::string& path) {
    auto r = rd(path);
    if (r.err == 0 && r.data.find('\0') != std::string::npos) return {kReadEmbeddedNul, {}};
    return r;
}

/// Reads `path`; on success returns the text. An absent / failed source hands its
/// {state, detail} to `state_row` and returns nullopt.
template <class StateRow>
std::optional<std::string> read_source(const FileReader& rd, Tally& t, const std::string& path,
                                       StateRow&& state_row) {
    auto r = checked_read(rd, path);
    if (r.err == 0) {
        ++t.readable;
        return std::move(r.data);
    }
    state_row(t.state_of(classify_read_errno(r.err), path));
    return std::nullopt;
}

inline void kv_source(const FileReader& rd, Tally& t, std::string_view action, const std::string& path,
                      std::string_view seps, std::span<const std::string_view> allow) {
    auto text = read_source(rd, t, path, [&](const auto& st) {
        t.row(format_kv_row(action, "source_state", kv_state_text(st), path));
    });
    if (!text) return;
    for (const auto& [k, v] : parse_kv_lines(*text, seps))
        if (allow.empty() || std::find(allow.begin(), allow.end(), k) != allow.end())
            t.row(format_kv_row(action, k, v, path));
}

/// `files` are distro ALTERNATIVES (Debian common-*, RHEL system-auth/password-auth), so one
/// ABSENT file is deliberately silent while any sibling exists; a refused or failed one is
/// always its own row, and all-absent is one `/etc/pam.d` absent row.
inline void pam_sources(const FileReader& rd, Tally& t, std::string_view action,
                        std::span<const std::string_view> files,
                        std::span<const std::string_view> types,
                        std::span<const std::string_view> modules) {
    std::size_t exist = 0; // present, refused or failed -- anything but definitively absent
    for (auto f : files) {
        const std::string path = "/etc/pam.d/" + std::string{f};
        auto r = checked_read(rd, path);
        if (r.err == 0) {
            ++exist;
            ++t.readable;
            for (const auto& p : parse_pam_lines(r.data))
                if (std::find(types.begin(), types.end(), p.type) != types.end() &&
                    std::find(modules.begin(), modules.end(), p.module) != modules.end())
                    t.row(format_kv_row(action, "pam." + p.type + "." + p.module,
                                        p.control + (p.args.empty() ? "" : " " + p.args), path));
            continue;
        }
        const auto st = t.state_of(classify_read_errno(r.err), path);
        if (st.first != "absent") {
            ++exist;
            t.row(format_kv_row(action, "source_state", kv_state_text(st), path));
        }
        if (f == files.back() && exist == 0)
            t.row(format_kv_row(action, "source_state", "absent", "/etc/pam.d"));
    }
}

inline void sudoers_file(const FileReader& rd, Tally& t, const std::string& path) {
    auto text = read_source(rd, t, path, [&](const auto& st) {
        t.row(format_sudoers_row(path, {st.first, "-", "-", "-", st.second.empty() ? "-" : st.second}));
    });
    if (!text) return;
    for (const auto& e : parse_sudoers(*text, kMaxRows - t.rows.size())) {
        if (t.capped) return; // rows past the cap are dropped: stop formatting (and parsing) here
        t.row(format_sudoers_row(path, e));
        // The fail-safe half of parse_user_spec: a NOPASSWD:/PASSWD: tag the parser could
        // not decode is an unmodelled row AND a failure, never a quiet `false`.
        if (e.kind == "unmodelled" && has_passwd_tag(e.commands)) {
            ++t.failed;
            t.acc.add_failure(path + ":undecoded_passwd_tag");
        }
    }
}

} // namespace detail

/// Collects the rows + status for a file-backed action. `Macos` password/lockout
/// come from pwpolicy, not files, and are not handled here.
inline Collected collect_file_policy(FileFlavor flavor, LocalPolicyAction action,
                                     const FileReader& rd, const DirLister& ls) {
    detail::Tally t;
    const auto prefix = action_row_prefix(action);
    // Shape the row-cap truncation marker like the action's own rows (sudoers is
    // 7 fields, the rest 4), so the notice can never break the wire contract.
    t.marker_prefix = std::string{prefix};
    t.marker_fields = action == LocalPolicyAction::Sudoers ? 7u : 4u;
    // FAIL CLOSED, not open. Both arms below are unreachable today -- execute()
    // rejects Unknown before any leg runs, and the macOS leg routes Password and
    // Lockout to pwpolicy before calling here -- but returning an empty Collected
    // would be status OK with zero rows, which apply_collected reports as a green
    // empty result. A named CONSTRAINED says what happened instead. (The
    // Password/Lockout arms read Linux paths and never consult `flavor`, so this
    // is also what stops a relaxed macOS early return quietly reading
    // /etc/login.defs on a Mac.)
    if (action == LocalPolicyAction::Unknown ||
        (flavor == FileFlavor::Macos &&
         (action == LocalPolicyAction::Password || action == LocalPolicyAction::Lockout)))
        return {{}, PolicyStatus::Constrained, "unsupported_action"};
    switch (action) {
    case LocalPolicyAction::Password: {
        detail::kv_source(rd, t, prefix, "/etc/login.defs", " \t", kLoginDefsPasswordKeys);
        detail::kv_source(rd, t, prefix, "/etc/security/pwquality.conf", " \t=", {});
        constexpr std::string_view files[] = {"common-password", "system-auth", "password-auth"};
        constexpr std::string_view types[] = {"password"};
        detail::pam_sources(rd, t, prefix, files, types, kPamPasswordModules);
        break;
    }
    case LocalPolicyAction::Lockout: {
        detail::kv_source(rd, t, prefix, "/etc/login.defs", " \t", kLoginDefsLockoutKeys);
        detail::kv_source(rd, t, prefix, "/etc/security/faillock.conf", " \t=", {});
        constexpr std::string_view files[] = {"common-auth", "common-account", "system-auth",
                                              "password-auth"};
        constexpr std::string_view types[] = {"auth", "account"};
        detail::pam_sources(rd, t, prefix, files, types, kPamLockoutModules);
        break;
    }
    case LocalPolicyAction::Audit: {
        const std::string path = flavor == FileFlavor::Macos ? "/etc/security/audit_control"
                                                             : "/etc/audit/audit.rules";
        auto text = detail::read_source(rd, t, path, [&](const auto& st) {
            t.row(format_kv_row(prefix, "source_state", detail::kv_state_text(st), path));
        });
        if (!text) break;
        if (flavor == FileFlavor::Macos) {
            for (const auto& [k, v] : parse_kv_lines(*text, ":")) t.row(format_kv_row(prefix, k, v, path));
            break;
        }
        const auto c = parse_auditd_rules_count(*text);
        // rules == watch_rules + syscall_rules + unmodelled_lines, and
        // control_lines accounts for every remaining non-comment line, so the
        // row set closes arithmetically and `rules` means what it says.
        t.row(format_kv_row(prefix, "rules", std::to_string(c.rules()), path));
        t.row(format_kv_row(prefix, "watch_rules", std::to_string(c.watches), path));
        t.row(format_kv_row(prefix, "syscall_rules", std::to_string(c.syscalls), path));
        t.row(format_kv_row(prefix, "unmodelled_lines", std::to_string(c.unmodelled), path));
        t.row(format_kv_row(prefix, "control_lines", std::to_string(c.control), path));
        t.row(format_kv_row(prefix, "enabled", c.enabled ? audit_enabled_token(*c.enabled) : "unset", path));
        break;
    }
    case LocalPolicyAction::Sudoers: {
        detail::sudoers_file(rd, t, "/etc/sudoers");
        const auto d = ls("/etc/sudoers.d");
        if (d.err != 0) {
            const auto st = t.state_of(classify_read_errno(d.err), "sudoers.d");
            t.row(format_sudoers_row("/etc/sudoers.d", {st.first, "-", "-", "-", st.second.empty() ? "-" : st.second}));
            break;
        }
        // Pair the failure with its row, like every other failure site in this
        // function. Counting one WITHOUT a row is what would let collect_file_policy
        // return a non-OK status with zero rows, and apply_collected's fallback would
        // then write its 4-field `<action>|status|...` shape into this action's
        // 7-field contract. It also puts the truncation on the wire instead of only
        // in the status reason. `unreadable` is already a declared sudoers kind.
        if (d.truncated) {
            t.acc.add_failure("sudoers.d:truncated");
            ++t.failed;
            t.row(format_sudoers_row("/etc/sudoers.d", {"unreadable", "-", "-", "-", "truncated"}));
        }
        for (const auto& n : d.names) {
            if (t.capped) break;
            const std::string path = "/etc/sudoers.d/" + n;
            if (sudoers_dir_entry_ignored(n))
                t.row(format_sudoers_row(path, {"ignored", "-", "-", "-", "name_ignored_by_sudo"}));
            else
                detail::sudoers_file(rd, t, path);
        }
        break;
    }
    case LocalPolicyAction::Unknown: break; // refused above; the switch stays exhaustive
    }
    return {std::move(t.rows), select_status(t.readable, t.denied, t.failed + (t.capped ? 1 : 0)),
            t.acc.reason()};
}

// ---- Windows secedit export -> rows (the Windows leg only reads and decodes the bytes) --------

struct SeceditRows {
    std::vector<std::string> rows;
    std::string failure_token; // non-empty -> CONSTRAINED; rows must not be trusted
};

inline constexpr std::string_view kSeceditPasswordKeys[] = {
    "MinimumPasswordAge", "MaximumPasswordAge", "MinimumPasswordLength",
    "PasswordComplexity", "PasswordHistorySize", "ClearTextPassword"};
inline constexpr std::string_view kSeceditLockoutKeys[] = {"LockoutBadCount", "ResetLockoutCount",
                                                           "LockoutDuration"};

/// [Event Audit] values are the AUDIT_* bitmask: 0 none, 1 success, 2 failure, 3 both;
/// anything else is the named `unmodelled:` state, never dropped and never "no data".
inline std::string secedit_audit_setting(std::string_view raw) {
    raw = trim_ws(raw);
    if (raw == "0") return "none";
    if (raw == "1") return "success";
    if (raw == "2") return "failure";
    if (raw == "3") return "success_failure";
    return "unmodelled:" + std::string{raw};
}

/// True only for a WHOLE export. `absent` is a real modal value (LockoutDuration when
/// LockoutBadCount=0), so a truncated file that exits 0 would otherwise report the keys it
/// lost as absent under OK. Measured on the-rig (Windows 11 Pro 10.0.26200, LocalSystem,
/// exit 0, 12828 bytes UTF-16LE, BOM FF FE): the sections run `[System Access]`,
/// `[Event Audit]`, `[Registry Values]`, `[Version]`, with `[Version]` LAST carrying
/// `signature="$CHICAGO$"` and `Revision=1`. Complete = both policy sections present and
/// the final section `[Version]` with that signature; anything else is
/// `secedit:export_incomplete`. Section/key names compare case-insensitively (INF rule).
inline bool secedit_export_complete(std::string_view text) {
    const auto ieq = [](std::string_view a, std::string_view b) {
        return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
                   return std::tolower(static_cast<unsigned char>(x)) == std::tolower(static_cast<unsigned char>(y));
               });
    };
    bool system_access = false, event_audit = false, signed_version = false;
    std::string_view last;
    for (auto raw : split_lines(text)) {
        const auto line = trim_ws(raw);
        if (!line.empty() && line.front() == '[' && line.back() == ']') {
            last = trim_ws(line.substr(1, line.size() - 2));
            system_access = system_access || ieq(last, "System Access");
            event_audit = event_audit || ieq(last, "Event Audit");
            signed_version = false; // only the FINAL section's signature counts
        } else if (const auto eq = line.find('='); ieq(last, "Version") && eq != std::string_view::npos &&
                   ieq(trim_ws(line.substr(0, eq)), "signature")) {
            signed_version = ieq(trim_ws(line.substr(eq + 1)), "\"$CHICAGO$\"");
        }
    }
    return system_access && event_audit && ieq(last, "Version") && signed_version;
}

/// `<action>|<key>|<value>|secedit` rows (audit: every [Event Audit] category). A key the
/// export does not carry is the row value `absent` (a modal state, no token); a missing
/// required section means the export is not the shape we read -- a failure token, never an
/// empty success. The leg refuses a NUL anywhere in the export first
/// (classify_decoded_export); a reported key or value holding one is still
/// `secedit:embedded_nul` here, so this mapper is safe on its own.
inline SeceditRows secedit_policy_rows(std::string_view action, const InfSections& sections) {
    SeceditRows out;
    const auto which = parse_local_policy_action(action);
    if (which == LocalPolicyAction::Unknown || which == LocalPolicyAction::Sudoers) {
        out.failure_token = "secedit:unsupported_action";
        return out;
    }
    const bool audit = which == LocalPolicyAction::Audit;
    const auto sec = sections.find(audit ? "Event Audit" : "System Access");
    if (sec == sections.end() || sec->second.empty()) {
        out.failure_token = audit ? "secedit:section_missing_event_audit"
                                  : "secedit:section_missing_system_access";
        return out;
    }
    const auto prefix = action_row_prefix(which);
    const auto nul = [&out](std::string_view k, std::string_view v) {
        if (k.find('\0') == std::string_view::npos && v.find('\0') == std::string_view::npos) return false;
        out = {{}, "secedit:embedded_nul"};
        return true;
    };
    if (audit) {
        for (const auto& [k, v] : sec->second) {
            if (nul(k, v)) return out;
            out.rows.push_back(format_kv_row(prefix, k, secedit_audit_setting(v), "secedit"));
        }
        return out;
    }
    for (const auto key : which == LocalPolicyAction::Lockout ? std::span<const std::string_view>{kSeceditLockoutKeys}
                                                              : std::span<const std::string_view>{kSeceditPasswordKeys}) {
        const auto it = sec->second.find(std::string{key});
        if (it != sec->second.end() && nul(key, it->second)) return out;
        out.rows.push_back(format_kv_row(prefix, key, it == sec->second.end() ? "absent" : it->second, "secedit"));
    }
    return out;
}

// ---- macOS pwpolicy ------------------------------------------------------------------------

struct PwPolicyItem {
    std::string category;   // policyCategoryAuthentication | policyCategoryPasswordContent | ...
    std::string identifier; // policyIdentifier
    std::string content;    // policyContent (Apple policy expression)
    /// True iff the plist actually carried a scalar `policyContent` key (even an empty one).
    /// `content` alone can't distinguish "key absent" from "key present, empty string" -- both
    /// leave `content.empty()` true -- and pwpolicy_rows() needs that distinction: a genuinely
    /// present-but-empty value renders `policy_content|present` (format_kv_row's own contract for
    /// any present-empty value), never the `missing_content` shape-defect reserved for a truly
    /// absent key.
    bool has_content = false;
    std::vector<std::pair<std::string, std::string>> params; // policyParameters scalars, key-sorted
    /// What the plist bridge could NOT read in the documented shape, each named once:
    /// `malformed_category` (the category's value is not an array), `malformed_policy`
    /// (an array element is not a dictionary), `malformed_identifier` / `malformed_content` /
    /// `malformed_parameter_value` (a modelled field is not a scalar), `malformed_parameters` (policyParameters
    /// is not a dictionary), `non_string_key` (a dictionary key that is not a string was
    /// skipped; at the plist root the item's category is empty), `unconvertible_key` (a
    /// string key with no UTF-8 rendering was skipped). pwpolicy_rows adds `missing_content`
    /// for an element that carries nothing reportable. A known category that
    /// is malformed would otherwise yield no rows and read as `policies|none`, a clean
    /// "nothing configured" -- so every defect becomes a row and a token, never silence.
    std::vector<std::string> defects;
};

/// `pwpolicy -getaccountpolicies` prints a non-plist banner line before the XML
/// (`Getting global account policies`); everything before `<?xml` is discarded.
inline std::optional<std::string_view> strip_to_xml(std::string_view raw) {
    const auto at = raw.find("<?xml");
    if (at == std::string_view::npos) return std::nullopt;
    return raw.substr(at);
}

/// Failure token for a finished pwpolicy run, or empty when the output is usable.
/// How the runner reported a child ending (yuzu::agent::TerminationReason, mirrored so this
/// header stays free of agent-core types; to_run_end in the legs header maps it). Both rung-2
/// legs classify from this, never from the runner's convenience flags, so a signalled or
/// cancelled run is named for what it was (agents/shared/subprocess_degradation.hpp).
enum class RunEnd { Exited, Deadline, Cancelled, Signaled, SpawnError, Other };

inline std::string classify_pwpolicy_run(RunEnd end, bool truncated, int exit_code) {
    switch (end) {
    case RunEnd::SpawnError:
        return "pwpolicy:spawn_error";
    case RunEnd::Deadline:
        return "pwpolicy:deadline";
    case RunEnd::Cancelled:
        return "pwpolicy:cancelled";
    case RunEnd::Signaled:
        return "pwpolicy:signaled";
    case RunEnd::Other:
        return "pwpolicy:unexpected_termination";
    case RunEnd::Exited:
        break;
    }
    if (truncated) return "pwpolicy:output_truncated";
    if (exit_code != 0) return "pwpolicy:exit_" + std::to_string(exit_code);
    return "";
}

/// `policyAttributePassword matches '.{N,}...'` -> N. Anything else -> nullopt (not guessed).
inline std::optional<unsigned> pwpolicy_min_length(std::string_view content) {
    const auto at = content.find(".{");
    if (at == std::string_view::npos) return std::nullopt;
    std::size_t i = at + 2;
    unsigned n = 0;
    const auto start = i;
    while (i < content.size() && content[i] >= '0' && content[i] <= '9' && i - start < 6)
        n = n * 10 + static_cast<unsigned>(content[i++] - '0');
    if (i == start || i + 1 >= content.size() || content[i] != ',' || content[i + 1] != '}')
        return std::nullopt;
    return n;
}

/// Rows + status for one action from the parsed policy items. Categories:
/// *Authentication -> lockout, policyCategoryPassword* -> password, anything else is
/// `unmodelled_category` in BOTH actions. A `policyAttribute*` parameter is its own key;
/// any other scalar parameter (e.g. `autoEnableInSeconds`, the lockout duration) is key
/// `unmodelled_parameter`, value `<name>=<value>` -- the key set stays closed and the
/// value is never dropped. Each
/// item defect (PwPolicyItem::defects) is a `source_state|unreadable:<defect>` row and a
/// `pwpolicy:<defect>` token (CONSTRAINED) in the action(s) its category routes to. No
/// matching policy and no defect is the modal row `policies|none`, not an error.
/// A policy identifier/category is normally a short, human-readable name (real captures: a few
/// dozen bytes -- see docs/samples/macos.txt). It becomes `src`, which is re-embedded in EVERY
/// row an item produces (one per parameter/defect), so bounding row COUNT alone (kMaxRows) is
/// not sufficient to bound total row BYTES: an item with a near-1MB identifier and thousands of
/// short parameters stays under kMaxRows while re-embedding that near-1MB string thousands of
/// times (governance SRE finding: the row-count cap alone permits hundreds of MB, not just the
/// adversarial-review probe's 100MB). Truncating the identifier before it becomes `src` bounds
/// the per-row amplification factor directly, independent of the row-count cap.
inline constexpr std::size_t kMaxSourceIdentifierBytes = 256;

inline Collected pwpolicy_rows(LocalPolicyAction action, const std::vector<PwPolicyItem>& items) {
    const auto prefix = action_row_prefix(action);
    std::vector<std::string> rows;
    yuzu::shared::ConstraintAccumulator acc;
    bool capped = false;
    // Bounds row growth the same way Tally::row() does for file-backed sources (parsers.hpp
    // above) -- this path had no cap of its own. Last slot reserved for the truncation marker,
    // same reservation logic as Tally::row. Row COUNT alone is not a row BYTES bound -- see
    // kMaxSourceIdentifierBytes above for the complementary per-row cap.
    const auto push_row = [&](std::string r) {
        if (rows.size() + 1 >= kMaxRows) {
            if (!capped) {
                acc.add_failure("row_cap");
                rows.push_back(format_kv_row(prefix, "source_state", "unreadable:row_cap", "pwpolicy"));
            }
            capped = true;
            return;
        }
        rows.push_back(std::move(r));
    };
    for (const auto& it : items) {
        if (capped) break;
        const bool lock = it.category.find("Authentication") != std::string::npos;
        const bool pw = it.category.rfind("policyCategoryPassword", 0) == 0;
        const std::string& named_raw = it.identifier.empty() ? it.category : it.identifier;
        // Cut at a UTF-8 character boundary, never mid-sequence -- same walk-back pattern
        // as installed_apps_parsers.hpp's list_field: back off while the byte AT the cut
        // point is a continuation byte (top bits 10xxxxxx), so a multibyte character
        // straddling kMaxSourceIdentifierBytes is excluded whole rather than severed
        // (fjarvis review finding, PR #5069 -- join_row's sanitize_utf8 below is a second,
        // independent line of defence, not a substitute for cutting cleanly here).
        std::string_view named = std::string_view{named_raw}.substr(0, kMaxSourceIdentifierBytes);
        if (named_raw.size() > kMaxSourceIdentifierBytes) {
            std::size_t cut = named.size();
            while (cut > 0 &&
                  (static_cast<unsigned char>(named_raw[cut]) & 0xC0) == 0x80)
                --cut;
            named = named.substr(0, cut);
        }
        const std::string src = named.empty() ? std::string{"pwpolicy"} : "pwpolicy:" + std::string{named};
        const auto defect_rows = [&] {
            for (const auto& d : it.defects) {
                push_row(format_kv_row(prefix, "source_state", "unreadable:" + d, src));
                acc.add_failure("pwpolicy:" + d);
            }
        };
        if (!lock && !pw) {
            // The root non_string_key placeholder has no category to name; a real
            // category -- even an empty-named one -- always keeps its row.
            if (!(it.category.empty() && !it.defects.empty()))
                push_row(format_kv_row(prefix, "unmodelled_category", it.category, "pwpolicy"));
            defect_rows();
            continue;
        }
        if (lock != (action == LocalPolicyAction::Lockout)) continue;
        if (!it.has_content && it.params.empty() && it.defects.empty()) {
            // A policy element carrying nothing this action can report is a shape defect,
            // not "no policy": without this row it would vanish, and could leave the clean
            // `policies|none` answer below. Gated on has_content, not content.empty() -- a
            // genuinely present-but-empty policyContent must fall through to the row below,
            // never collapse into this shape-defect case.
            push_row(format_kv_row(prefix, "source_state", "unreadable:missing_content", src));
            acc.add_failure("pwpolicy:missing_content");
            continue;
        }
        if (it.has_content) push_row(format_kv_row(prefix, "policy_content", it.content, src));
        // Gated on pw: minimum_length is a password_policy-only key (README-documented
        // scope). Without this gate, a lockout/Authentication item whose content
        // coincidentally matches the `.{N,}` shape leaks minimum_length into lockout_policy
        // rows too (fjarvis review finding, PR #5069).
        if (pw) {
            if (const auto n = pwpolicy_min_length(it.content))
                push_row(format_kv_row(prefix, "minimum_length", std::to_string(*n), src));
        }
        for (const auto& [k, v] : it.params) {
            if (k.rfind("policyAttribute", 0) == 0) push_row(format_kv_row(prefix, k, v, src));
            else push_row(format_kv_row(prefix, "unmodelled_parameter", k + "=" + v, src));
        }
        defect_rows();
    }
    if (rows.empty()) rows.push_back(format_kv_row(prefix, "policies", "none", "pwpolicy"));
    return {std::move(rows), acc.any_failure() ? PolicyStatus::Constrained : PolicyStatus::Ok,
            acc.reason()};
}

} // namespace yuzu::local_security_policy
