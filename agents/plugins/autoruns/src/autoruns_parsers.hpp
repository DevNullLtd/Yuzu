/**
 * autoruns_parsers.hpp — pure parsing and formatting for the autoruns plugin.
 *
 * Everything in this header is a PURE function: no OS call, no file read, no
 * process spawn. Every OS-facing byte a per-OS leg (P12/P13/P14) reads is
 * handed to something here already extracted into plain strings/bytes, which
 * is what makes every parser fixture-testable without an OS harness.
 *
 * ROW SCHEMA (fixed-width; "-" where a value is inapplicable to that row):
 *   autorun|<source_id>|<catalog_version>|<location>|<entry>|<target>|<args>|
 *          <enabled>|<scope>|<user>|<signed>|<mtime>
 *   source|<id>|<supported|constrained|unsupported>|<row_count>|<reason>
 *
 * ESCAPING. This plugin does NOT use yuzu::util::safe_output_field's
 * backslash-pipe convention. Untrusted fields here (location, entry, target,
 * args, user) fold a literal '|' to U+2502 (BOX DRAWINGS LIGHT VERTICAL, │)
 * and CR/LF to a space, which keeps every row a fixed field count under a
 * naive split('|') -- deliberate, because a positional consumer reading
 * `autorun|` rows should never need an escape-aware splitter to find field 7
 * (enabled). The substitution is lossy (a literal │ in source data is
 * indistinguishable from an escaped │), which is an accepted trade for
 * positional simplicity -- the same trade-off class as safe_output_field's
 * own documented lossiness on backslashes.
 */
#pragma once

#include "autoruns_catalog.hpp"

#include <yuzu/plugin.h> // YuzuSupportLevel

// ConstraintAccumulator lives in agents/shared/ (Wave-7b prerequisite pass,
// 2026-09-14) so execution_artifacts and app_usage can reuse it instead of
// reinventing or copying it; see that header's banner for the full history.
// This plugin's own call sites use it fully qualified
// (`yuzu::shared::ConstraintAccumulator`), matching `posix_dir_walk.hpp`'s
// existing convention in this same directory.
#include <constraint_accumulator.hpp>

// Real XML parsing for Windows Task Scheduler XML (parse_task_xml, below) --
// see that function's banner for why this replaced hand-rolled scanning.
// Same library this repo already trusts for equally-adversarial XML
// (server/core/src/saml_provider.cpp). libxml2's own headers are C headers
// with internal extern "C" guards, safe to include directly from C++.
#include <libxml/parser.h>
#include <libxml/tree.h>

#include <array>
#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::autoruns {

// ── fixed vocabularies ───────────────────────────────────────────────────

/// `unmodelled` is a DIFFERENT fact from `unknown`: unmodelled means the
/// input was in a shape this parser deliberately does not decode (e.g. a
/// StartupApproved blob whose byte0 is neither 0x02 nor 0x03, or a truncated
/// one) -- the parser saw the byte and chose not to guess. `unknown` means no
/// enablement signal exists on this source at all (e.g. a launchd plist with
/// no `Disabled` key: launchd's own documented default is enabled, but this
/// plugin reports enabled once it has actually reasoned about the default --
/// `unknown` is reserved for sources with no default to reason from).
enum class Enabled { enabled, disabled, unmodelled, unknown };

constexpr std::string_view enabled_token(Enabled e) noexcept {
    switch (e) {
    case Enabled::enabled:    return "enabled";
    case Enabled::disabled:   return "disabled";
    case Enabled::unmodelled: return "unmodelled";
    case Enabled::unknown:    return "unknown";
    }
    return "unknown";
}

enum class Scope { system, user };

constexpr std::string_view scope_token(Scope s) noexcept {
    switch (s) {
    case Scope::system: return "system";
    case Scope::user:   return "user";
    }
    return "system";
}

/// Deliberately narrow (Decision, PR11.4). `apple_system` is a PATH judgement
/// only -- anything under /System/Library is Apple's, verbatim, with no code-
/// signature check performed. `not_checked` is the honest default everywhere
/// else: this plugin has not asked SecStaticCode anything. A future PR11.4
/// wiring a real signature check adds values here; it does not repurpose
/// these two.
enum class Signed { apple_system, not_checked, unmodelled };

constexpr std::string_view signed_token(Signed s) noexcept {
    switch (s) {
    case Signed::apple_system: return "apple_system";
    case Signed::not_checked:  return "not_checked";
    case Signed::unmodelled:   return "unmodelled";
    }
    return "not_checked";
}

/// macOS-only judgement, callable on any OS (it is pure path text matching --
/// no filesystem call). Anything not under /System/Library is `not_checked`.
inline Signed signed_from_path(std::string_view path) noexcept {
    constexpr std::string_view kSystemPrefix = "/System/Library/";
    if (path.size() >= kSystemPrefix.size() && path.substr(0, kSystemPrefix.size()) == kSystemPrefix)
        return Signed::apple_system;
    return Signed::not_checked;
}

constexpr std::string_view support_token(YuzuSupportLevel s) noexcept {
    switch (s) {
    case YUZU_SUPPORT_SUPPORTED:   return "supported";
    case YUZU_SUPPORT_CONSTRAINED: return "constrained";
    default:                       return "unsupported"; // UNSUPPORTED / PLANNED / UNDECLARED
    }
}

// ── the row, and its formatter ───────────────────────────────────────────

struct Row {
    SourceId source_id;
    int catalog_version;
    std::string location;
    std::string entry;
    std::string target;
    std::string args;
    Enabled enabled;
    Scope scope;
    std::string user;
    Signed signed_state;
    std::int64_t mtime;
};

/// Fold '|' -> U+2502 and CR/LF -> space. See the file banner for why this is
/// a different convention from yuzu::util::safe_output_field.
inline std::string sanitize_autorun_field(std::string_view value) {
    std::string out;
    out.reserve(value.size());
    for (char ch : value) {
        if (ch == '\r' || ch == '\n')
            out += ' ';
        else if (ch == '|')
            out += "\u2502";
        else
            out += ch;
    }
    return out;
}

/// autorun|<source_id>|<catalog_version>|<location>|<entry>|<target>|<args>|
///        <enabled>|<scope>|<user>|<signed>|<mtime>
/// Field index 7 (0-based, "autorun" itself at 0) is `enabled` --
/// server/core/src/result_parsing.hpp's `cell_hints()` table hard-codes that
/// index for the autoruns `enabled=unknown` dashboard hint (#4187); a column
/// inserted before `enabled` here must update that table's index too.
inline std::string format_row(const Row& row) {
    std::string out = "autorun|";
    out += source_id_string(row.source_id);
    out += '|';
    out += std::to_string(row.catalog_version);
    out += '|';
    out += sanitize_autorun_field(row.location);
    out += '|';
    out += sanitize_autorun_field(row.entry);
    out += '|';
    out += sanitize_autorun_field(row.target);
    out += '|';
    out += sanitize_autorun_field(row.args);
    out += '|';
    out += enabled_token(row.enabled);
    out += '|';
    out += scope_token(row.scope);
    out += '|';
    out += sanitize_autorun_field(row.user);
    out += '|';
    out += signed_token(row.signed_state);
    out += '|';
    out += std::to_string(row.mtime);
    return out;
}

/// source|<id>|<supported|constrained|unsupported>|<row_count>|<reason>
/// `rows` is std::nullopt for a DECLARED-only status (the `catalog` action,
/// which never executed a read) -- rendered "-", distinct from a REAL zero
/// count from an actual (constrained-or-supported) collection attempt that
/// genuinely found nothing.
inline std::string format_source_status(SourceId id, YuzuSupportLevel support,
                                        std::optional<std::size_t> rows,
                                        std::string_view reason) {
    std::string out = "source|";
    out += source_id_string(id);
    out += '|';
    out += support_token(support);
    out += '|';
    out += rows ? std::to_string(*rows) : "-";
    out += '|';
    out += sanitize_autorun_field(reason);
    return out;
}

// ── UTF-16LE decode (pure; needed for reg(1)-export hex(2) blobs) ────────

/// Decodes UTF-16LE bytes to UTF-8, stopping at a trailing NUL code unit if
/// present (registry string data is NUL-terminated within its declared
/// length). BMP-only: a real autorun target is never a supplementary-plane
/// path, and this is not a general-purpose text codec. An odd byte count (a
/// truncated code unit) stops decoding at the last complete unit rather than
/// reading past the buffer -- the truncation is silent by design here because
/// callers that care (parse_reg_run_values) detect truncation themselves from
/// the surrounding hex-byte count.
namespace detail {
inline void append_utf8(std::string& out, std::uint32_t cp) {
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
} // namespace detail

inline std::string utf16le_to_utf8(std::span<const unsigned char> bytes) {
    std::string out;
    out.reserve(bytes.size());
    std::size_t i = 0;
    // `i + 1 < bytes.size()`, not `<=`: a single dangling trailing byte (an
    // odd total length -- a truncated final UTF-16 code unit) is silently
    // dropped rather than emitting a replacement character for it. This is
    // deliberate, matching this function's own documented contract (see the
    // file banner above): a truncated code unit is not a decodable
    // character at all, so there is nothing to represent -- callers that
    // care about truncation (parse_reg_run_values) detect it from the
    // surrounding hex-byte count, not from this function's output shape.
    while (i + 1 < bytes.size()) {
        const std::uint16_t unit =
            static_cast<std::uint16_t>(bytes[i]) | (static_cast<std::uint16_t>(bytes[i + 1]) << 8);
        i += 2;
        if (unit == 0) break; // NUL terminator
        if (unit >= 0xD800 && unit <= 0xDBFF) {
            // High surrogate -- pair with a following low surrogate into a
            // real supplementary-plane code point (4-byte UTF-8), rather
            // than encoding each surrogate half individually (CESU-8,
            // technically invalid UTF-8). A high surrogate with no valid
            // low surrogate following it (end of buffer, or the next unit
            // isn't a low surrogate) is unpaired -- emit U+FFFD rather than
            // a half-formed sequence.
            if (i + 1 < bytes.size()) {
                const std::uint16_t next = static_cast<std::uint16_t>(bytes[i]) |
                                           (static_cast<std::uint16_t>(bytes[i + 1]) << 8);
                if (next >= 0xDC00 && next <= 0xDFFF) {
                    i += 2;
                    const std::uint32_t cp = 0x10000 +
                                             ((static_cast<std::uint32_t>(unit) - 0xD800) << 10) +
                                             (static_cast<std::uint32_t>(next) - 0xDC00);
                    detail::append_utf8(out, cp);
                    continue;
                }
            }
            detail::append_utf8(out, 0xFFFD); // unpaired high surrogate
            continue;
        }
        if (unit >= 0xDC00 && unit <= 0xDFFF) {
            detail::append_utf8(out, 0xFFFD); // lone low surrogate
            continue;
        }
        detail::append_utf8(out, unit);
    }
    return out;
}

// ── 1. split_command_line ────────────────────────────────────────────────

struct SplitCommand {
    std::string target;
    std::string args;
};

/// Splits a Windows command-line string into the invoked target and its
/// argument tail. Handles a QUOTED target (the common Run-key shape --
/// `"C:\Program Files\...\x.exe" -flag`) and a bare, space-delimited target
/// (rundll32-style -- `rundll32.exe shell32.dll,Control_RunDLL` splits at the
/// first space; the DLL/entry-point tail travels in `args` unparsed, which is
/// correct here since this function's job is target/args separation, not DLL
/// entry-point resolution).
/// Windows Run-key convention -- NOT CommandLineToArgvW's own backslash-
/// collapsing rules (a different consumer this string never passes
/// through): backslashes here are ordinary path separators, verbatim in
/// the extracted target, never unescaped. The only thing this function
/// decides about a backslash run is whether it makes the NEXT `"` a real
/// closing quote or an escaped one -- an EVEN run (0, 2, 4, ...) means the
/// quote terminates; an ODD run means it's escaped (`\"` embeds a literal
/// quote character) and scanning continues past it. A bare single-
/// backslash check (this function's prior form) gets this wrong for any
/// run of 2 or more, e.g. `"C:\dir\\" -flag` -- two backslashes before
/// the closing quote is an EVEN run (a plain trailing path separator, the
/// quote genuinely closes there), but the old check saw ONE backslash
/// immediately before it and treated the quote as escaped, scanning past
/// the real close into the argument tail.
inline SplitCommand split_command_line(std::string_view raw) {
    std::size_t start = raw.find_first_not_of(' ');
    if (start == std::string_view::npos) return {};
    raw.remove_prefix(start);

    SplitCommand out;
    if (raw.front() == '"') {
        std::size_t close = 1;
        while (close < raw.size()) {
            if (raw[close] == '"') {
                std::size_t backslashes = 0;
                std::size_t k = close;
                while (k > 1 && raw[k - 1] == '\\') {
                    ++backslashes;
                    --k;
                }
                if (backslashes % 2 == 0) break; // even run -- this quote terminates
            }
            ++close;
        }
        out.target = std::string{raw.substr(1, close - 1)};
        if (close < raw.size()) {
            std::size_t rest = raw.find_first_not_of(' ', close + 1);
            if (rest != std::string_view::npos) out.args = std::string{raw.substr(rest)};
        }
    } else {
        std::size_t sp = raw.find(' ');
        if (sp == std::string_view::npos) {
            out.target = std::string{raw};
        } else {
            out.target = std::string{raw.substr(0, sp)};
            std::size_t rest = raw.find_first_not_of(' ', sp + 1);
            if (rest != std::string_view::npos) out.args = std::string{raw.substr(rest)};
        }
    }
    return out;
}

// ── 2. parse_reg_run_values (reg(1)-export text) ─────────────────────────

struct RegValue {
    std::string name;
    std::string data; // resolved string data; empty for a type this parser skips
};

namespace detail {

inline std::string strip_cr(std::string_view line) {
    if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
    return std::string{line};
}

/// Unescapes reg(1)-export quoted-string syntax: `\"` -> `"`, `\\` -> `\`.
inline std::string unescape_reg_quoted(std::string_view body) {
    std::string out;
    out.reserve(body.size());
    for (std::size_t i = 0; i < body.size(); ++i) {
        if (body[i] == '\\' && i + 1 < body.size() && (body[i + 1] == '"' || body[i + 1] == '\\')) {
            out += body[i + 1];
            ++i;
        } else {
            out += body[i];
        }
    }
    return out;
}

/// Parses a comma-separated hex byte list, following reg(1)'s `\`-continued-
/// line convention (a trailing backslash means "more bytes follow on the next
/// physical line"). `lines` starts at the value's first line and `idx` is
/// advanced past every line this value consumed.
inline std::vector<unsigned char> collect_hex_bytes(const std::vector<std::string>& lines,
                                                    std::size_t& idx, std::string_view first_tail) {
    std::vector<unsigned char> out;
    std::string_view tail = first_tail;
    for (;;) {
        bool continued = !tail.empty() && tail.back() == '\\';
        std::string_view body = continued ? tail.substr(0, tail.size() - 1) : tail;
        std::size_t pos = 0;
        while (pos < body.size()) {
            while (pos < body.size() && (body[pos] == ' ' || body[pos] == ',')) ++pos;
            std::size_t start = pos;
            while (pos < body.size() && body[pos] != ',') ++pos;
            if (pos > start) {
                std::string_view tok = body.substr(start, pos - start);
                // trim trailing spaces inside the token
                while (!tok.empty() && tok.back() == ' ') tok.remove_suffix(1);
                if (!tok.empty()) {
                    unsigned int v = 0;
                    for (char c : tok) {
                        v <<= 4;
                        if (c >= '0' && c <= '9') v |= static_cast<unsigned int>(c - '0');
                        else if (c >= 'a' && c <= 'f') v |= static_cast<unsigned int>(c - 'a' + 10);
                        else if (c >= 'A' && c <= 'F') v |= static_cast<unsigned int>(c - 'A' + 10);
                    }
                    out.push_back(static_cast<unsigned char>(v & 0xFF));
                }
            }
        }
        if (!continued || idx >= lines.size()) break;
        tail = lines[idx];
        ++idx;
        // reg-export continuation lines carry leading whitespace indentation
        std::size_t nz = tail.find_first_not_of(' ');
        tail = nz == std::string_view::npos ? std::string_view{} : tail.substr(nz);
    }
    return out;
}

} // namespace detail

/// Parses reg(1)-export text (`Windows Registry Editor Version 5.00` header,
/// `[KEY]` section markers, `"name"=value` assignments) and returns the
/// REG_SZ / REG_EXPAND_SZ values found, across every section in the text --
/// callers pass text scoped to the one key they care about. Every other
/// value type (`dword:`, `hex(b):` QWORD, bare `hex:` binary) is recognised
/// and skipped rather than mis-decoded: those are not string targets a
/// Run-style key needs, and this parser never guesses at binary data it
/// cannot resolve to text.
///
/// Input is UTF-8 text: the real capture this is fixture-tested against is a
/// UTF-16LE file (`reg export`'s own output encoding) and callers decode that
/// file-level encoding themselves before calling this -- this function's
/// concern is reg(1)'s TEXT GRAMMAR, not the file's byte encoding, and hex(2)
/// blobs (which ARE UTF-16LE bytes, just spelled as hex inside that grammar)
/// go through utf16le_to_utf8 internally regardless.
inline std::vector<RegValue> parse_reg_run_values(std::string_view text) {
    std::vector<std::string> lines;
    {
        std::size_t pos = 0;
        while (pos <= text.size()) {
            std::size_t nl = text.find('\n', pos);
            if (nl == std::string_view::npos) {
                if (pos < text.size()) lines.push_back(detail::strip_cr(text.substr(pos)));
                break;
            }
            lines.push_back(detail::strip_cr(text.substr(pos, nl - pos)));
            pos = nl + 1;
        }
    }

    std::vector<RegValue> out;
    for (std::size_t i = 0; i < lines.size(); ++i) {
        std::string_view line = lines[i];
        if (line.empty() || line.front() != '"') continue;
        std::size_t name_end = 1;
        while (name_end < line.size() &&
              !(line[name_end] == '"' && line[name_end - 1] != '\\'))
            ++name_end;
        if (name_end >= line.size()) continue;
        std::string name = detail::unescape_reg_quoted(line.substr(1, name_end - 1));
        std::size_t eq = line.find('=', name_end + 1);
        if (eq == std::string_view::npos) continue;
        std::string_view rhs = line.substr(eq + 1);

        RegValue rv;
        rv.name = std::move(name);
        if (!rhs.empty() && rhs.front() == '"') {
            std::size_t close = 1;
            while (close < rhs.size() && !(rhs[close] == '"' && rhs[close - 1] != '\\')) ++close;
            rv.data = detail::unescape_reg_quoted(rhs.substr(1, close - 1));
            out.push_back(std::move(rv));
        } else if (rhs.rfind("hex(2):", 0) == 0) {
            std::size_t consumed = i + 1;
            auto bytes = detail::collect_hex_bytes(lines, consumed, rhs.substr(7));
            i = consumed - 1;
            rv.data = utf16le_to_utf8(std::span<const unsigned char>{bytes.data(), bytes.size()});
            out.push_back(std::move(rv));
        }
        // dword:, hex:, hex(b): and any other type: not a string target; skipped.
    }
    return out;
}

// ── 3. parse_startup_approved_blob ───────────────────────────────────────

/// StartupApproved\Run stores a 12-byte blob per value; byte 0 is the
/// enablement flag (0x02 = enabled, 0x03 = disabled), the rest a FILETIME the
/// UI last toggled it. Any other length, or a byte 0 outside {0x02, 0x03},
/// is `unmodelled` -- this plugin does not guess at an undocumented blob
/// shape, which is exactly what a 3-byte reconstruction (truncated read)
/// pins.
inline Enabled parse_startup_approved_blob(std::span<const unsigned char> blob) noexcept {
    if (blob.size() != 12) return Enabled::unmodelled;
    if (blob[0] == 0x02) return Enabled::enabled;
    if (blob[0] == 0x03) return Enabled::disabled;
    return Enabled::unmodelled;
}

// ── 4. parse_winlogon_shell / parse_winlogon_userinit ────────────────────

struct WinlogonValue {
    std::vector<std::string> entries; // non-empty, comma-split tokens
    bool flag_beyond_default = false;
};

namespace detail {

inline std::vector<std::string> comma_split_nonempty(std::string_view value) {
    std::vector<std::string> out;
    std::size_t pos = 0;
    while (pos <= value.size()) {
        std::size_t comma = value.find(',', pos);
        std::string_view tok = comma == std::string_view::npos ? value.substr(pos)
                                                                : value.substr(pos, comma - pos);
        if (!tok.empty()) out.emplace_back(tok);
        if (comma == std::string_view::npos) break;
        pos = comma + 1;
    }
    return out;
}

inline bool ends_with_ci(std::string_view s, std::string_view suffix) {
    if (s.size() < suffix.size()) return false;
    std::string_view tail = s.substr(s.size() - suffix.size());
    for (std::size_t i = 0; i < suffix.size(); ++i)
        if (std::tolower(static_cast<unsigned char>(tail[i])) !=
            std::tolower(static_cast<unsigned char>(suffix[i])))
            return false;
    return true;
}

inline WinlogonValue parse_winlogon_value(std::string_view value, std::string_view default_exe) {
    WinlogonValue out;
    out.entries = comma_split_nonempty(value);
    for (const auto& e : out.entries)
        if (!ends_with_ci(e, default_exe)) out.flag_beyond_default = true;
    return out;
}

} // namespace detail

/// Windows' documented default Shell is `explorer.exe`; anything else in the
/// comma list (a second shell, or a hijacked path) flags.
inline WinlogonValue parse_winlogon_shell(std::string_view value) {
    return detail::parse_winlogon_value(value, "explorer.exe");
}

/// Userinit's documented default is `C:\Windows\system32\userinit.exe,` --
/// note the trailing comma producing an EMPTY second token, which
/// comma_split_nonempty drops rather than flagging (an empty slot is not an
/// extra program).
inline WinlogonValue parse_winlogon_userinit(std::string_view value) {
    return detail::parse_winlogon_value(value, "userinit.exe");
}

// ── 5. parse_appinit_dlls ─────────────────────────────────────────────────

/// AppInit_DLLs is a whitespace- (historically also comma-) separated DLL
/// path list. An empty value (the common, unpopulated case -- this plugin's
/// own real-capture fixture) yields an empty list, not a one-element list
/// containing "".
inline std::vector<std::string> parse_appinit_dlls(std::string_view value) {
    std::vector<std::string> out;
    std::size_t pos = 0;
    while (pos < value.size()) {
        while (pos < value.size() && (value[pos] == ' ' || value[pos] == ',')) ++pos;
        std::size_t start = pos;
        while (pos < value.size() && value[pos] != ' ' && value[pos] != ',') ++pos;
        if (pos > start) out.emplace_back(value.substr(start, pos - start));
    }
    return out;
}

// ── 6. parse_ifeo_debugger ────────────────────────────────────────────────

struct IfeoEntry {
    std::string exe_name;
    std::string debugger;
    bool has_debugger = false;
};

/// IFEO's persistence mechanism is the OPTIONAL `Debugger` value under an
/// exe's subkey: when present, that program launches instead of the named
/// exe. `debugger_value` empty means "no Debugger value was read for this
/// subkey" (this plugin's own real-capture fixture: `appverif.exe` carries
/// only `CfgOptions`, no Debugger) -- has_debugger is false, not a guess.
inline IfeoEntry parse_ifeo_debugger(std::string_view exe_name, std::string_view debugger_value) {
    IfeoEntry out;
    out.exe_name = std::string{exe_name};
    if (!debugger_value.empty()) {
        out.debugger = std::string{debugger_value};
        out.has_debugger = true;
    }
    return out;
}

// ── 6b. resolve_profile_shell_folder (win_startup_folder_user redirect) ──

/// Outcome of resolving a `User Shell Folders\Startup` registry value
/// against a SPECIFIC enumerated profile -- `path` is the resolved
/// directory, or nullopt when the value could not be turned into a usable
/// path; `constraint` is a stable reason token for the caller's
/// `constrained` status whenever `path` is nullopt AND the value wasn't
/// simply absent (empty `value` in, empty `constraint` out, is the "not
/// configured" case -- not a failure).
struct ShellFolderResolution {
    std::optional<std::string> path;
    std::string_view constraint{};
};

namespace detail {
inline bool ieq_ascii(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i])))
            return false;
    }
    return true;
}
} // namespace detail

/// Resolves a `User Shell Folders\Startup` registry value against the
/// ENUMERATED PROFILE's own identity, never the calling process's
/// environment (#4219: the agent runs as LocalSystem, and Windows
/// populates this value with `%USERPROFILE%`-style tokens on essentially
/// every profile at creation -- expanding those against LocalSystem's own
/// environment resolves to a path that normally doesn't exist, silently
/// under-reporting the profile's real Startup entries).
///
/// `REG_SZ` is used as a literal path, no expansion. `REG_EXPAND_SZ` is
/// scanned for `%NAME%` tokens by this function itself -- never handed to
/// `ExpandEnvironmentStringsW`, which has no notion of "a different user's
/// profile" to expand against -- with two token classes:
///   - User-scoped (resolved from `profile_path`/`profile_name`, no lookup
///     needed): `USERPROFILE`, `APPDATA` (`profile_path\AppData\Roaming`),
///     `LOCALAPPDATA` (`profile_path\AppData\Local`), `USERNAME`.
///   - Machine-scoped (identical for every user on this host, so reading
///     the agent's OWN environment is correct for these specifically --
///     `SystemDrive`, `SystemRoot`, `windir`, `ProgramData`,
///     `ALLUSERSPROFILE`, `PUBLIC`, `ProgramFiles`, `ProgramFiles(x86)`):
///     resolved via the caller-supplied `machine_var` lookup.
/// Any other token name, an unterminated `%`, an empty `%%` token, or an
/// allowlisted machine token `machine_var` can't supply is
/// `startup_redirect_unresolved` -- never a silent guess. Any `type_name`
/// other than `REG_SZ`/`REG_EXPAND_SZ` is `startup_redirect_bad_type`. An
/// empty `value` is "not configured" (nullopt path, empty constraint) --
/// the overwhelmingly common case for a profile with no real redirect.
inline ShellFolderResolution resolve_profile_shell_folder(
    std::string_view value, std::string_view type_name, std::string_view profile_path,
    std::string_view profile_name,
    const std::function<std::optional<std::string>(std::string_view)>& machine_var) {
    if (value.empty()) return {};
    if (type_name != "REG_SZ" && type_name != "REG_EXPAND_SZ")
        return {std::nullopt, "startup_redirect_bad_type"};
    if (type_name == "REG_SZ") return {std::string{value}, {}};

    static constexpr std::array<const char*, 8> kMachineAllowlist{
        "SystemDrive",     "SystemRoot", "windir",       "ProgramData",
        "ALLUSERSPROFILE", "PUBLIC",     "ProgramFiles", "ProgramFiles(x86)"};

    std::string out;
    out.reserve(value.size());
    std::size_t i = 0;
    while (i < value.size()) {
        if (value[i] != '%') {
            out += value[i];
            ++i;
            continue;
        }
        const std::size_t close = value.find('%', i + 1);
        if (close == std::string_view::npos) return {std::nullopt, "startup_redirect_unresolved"};
        const std::string_view name = value.substr(i + 1, close - i - 1);
        if (name.empty()) return {std::nullopt, "startup_redirect_unresolved"};

        std::optional<std::string> resolved;
        if (detail::ieq_ascii(name, "USERPROFILE")) {
            resolved = std::string{profile_path};
        } else if (detail::ieq_ascii(name, "APPDATA")) {
            resolved = std::string{profile_path} + "\\AppData\\Roaming";
        } else if (detail::ieq_ascii(name, "LOCALAPPDATA")) {
            resolved = std::string{profile_path} + "\\AppData\\Local";
        } else if (detail::ieq_ascii(name, "USERNAME")) {
            resolved = std::string{profile_name};
        } else {
            for (const char* m : kMachineAllowlist) {
                if (detail::ieq_ascii(name, m)) {
                    resolved = machine_var(name);
                    break;
                }
            }
        }
        if (!resolved.has_value()) return {std::nullopt, "startup_redirect_unresolved"};
        out += *resolved;
        i = close + 1;
    }
    return {out, {}};
}

// ── 7. parse_task_xml (libxml2-based Task Scheduler XML parser) ──────────

/// One `<Exec>` action within a task's `<Actions>` block. Task Scheduler
/// supports up to 32 sequential actions per task, ALL of which it executes
/// in order -- surfacing only the first silently hides the rest from an
/// operator (a benign first action, persistence-payload second action is a
/// real scenario, not a hypothetical one).
struct TaskAction {
    std::string command;
    std::string arguments;
};

/// Why parse_task_xml rejected a document (TaskInfo::parsed_ok == false) --
/// `none` when parsing succeeded. A caller that wants a single reason token
/// can collapse most of these to "malformed" (they all mean "this was not a
/// usable Task Scheduler document"); `oversized` is kept distinguishable
/// because it is reachable from an entirely different cause (a runaway/
/// corrupt get_Xml() BSTR) than a genuine XML syntax problem, and worth its
/// own token for anyone triaging a fleet-wide reason breakdown (#4184).
// A new value here MUST get its own case in task_reject_reason_token below --
// the switch there deliberately has no `default:` label so -Wswitch flags a
// missing case (non-fatal, werror=false project-wide, so this comment is the
// backstop a human reviewer needs since the warning alone can be missed).
enum class TaskReject { none, empty, malformed, dtd, wrong_root, oversized };

/// The `win_scheduled_tasks` wire-reason token for a parse rejection --
/// pure, so the mapping (not just TaskReject itself) is unit-testable on
/// every build host, not only reachable by reading the Windows-only COM
/// call site that consumes it. `oversized` gets its own token (a runaway/
/// corrupt `get_Xml()` BSTR is a different failure shape than a genuine
/// XML syntax problem, #4184); every other non-`none` TaskReject
/// (`empty`/`malformed`/`dtd`/`wrong_root`) collapses to the existing
/// `"malformed"` token -- a caller reading the wire reason doesn't need
/// every rejection SHAPE distinguished, just this one different CAUSE.
/// `none` (a successful parse) has no reason to report and returns "".
inline std::string_view task_reject_reason_token(TaskReject reject) noexcept {
    // No `default:` label -- see TaskReject's own comment above: a new enum
    // value with no case here trips -Wswitch. The trailing return after the
    // switch exists only to satisfy every compiler's return-path analysis,
    // never to silently absorb a genuinely new, unhandled TaskReject value.
    switch (reject) {
    case TaskReject::none: return "";
    case TaskReject::oversized: return "oversized";
    case TaskReject::empty:
    case TaskReject::malformed:
    case TaskReject::dtd:
    case TaskReject::wrong_root: return "malformed";
    }
    return "malformed";
}

struct TaskInfo {
    std::vector<TaskAction> actions; // one per <Exec>, in document order
    bool has_unmodelled_action = false; // an <Actions> child this scanner
                                        // doesn't decode (e.g. <ComHandler>,
                                        // <SendEmail>, <ShowMessage>) is
                                        // present alongside/instead of <Exec>
    bool enabled = true; // Task Scheduler's own documented default
    std::string user_id;
    bool has_triggers = false;
    std::string registration_date; // raw <RegistrationInfo>/<Date> text,
                                    // empty if absent -- read through this
                                    // same libxml2 tree (caller converts to
                                    // epoch); never a second raw-text scan.
    // true ONLY once a well-formed, <Task>-rooted document was parsed --
    // false means a GENUINE parse failure (empty input, malformed XML, a
    // rejected DTD, or an unexpected root element), never "a well-formed
    // task that happens to have no triggers or actions". A task with no
    // <Triggers>/<Actions> children is a legitimate boring task and still
    // reports parsed_ok=true with empty actions/has_triggers -- conflating
    // "no elements" with "parse failed" is exactly the defect this field
    // exists to stop a caller from reintroducing (PR #4154 round 9 blocker).
    bool parsed_ok = false;
    // Set alongside every parsed_ok=false return -- see TaskReject's own
    // banner. Left at ::none whenever parsed_ok is true.
    TaskReject reject = TaskReject::none;
};

namespace detail {

/// Task Scheduler's `Enabled` element is typed `xsd:boolean`, whose valid
/// lexical space is `"true"`/`"false"`/`"1"`/`"0"`, optionally
/// whitespace-padded (`" false "`) -- a bare `== "false"` string compare
/// treats `"0"` and any padded form as live, which is the false-positive
/// direction (an inert trigger read as firing).
inline bool xsd_boolean_is_false(std::string_view v) {
    const std::size_t b = v.find_first_not_of(" \t\r\n");
    if (b == std::string_view::npos) return false; // empty/whitespace-only: not a recognized false
    const std::size_t e = v.find_last_not_of(" \t\r\n");
    const std::string_view trimmed = v.substr(b, e - b + 1);
    return trimmed == "false" || trimmed == "0";
}

/// RAII owner for an xmlDocPtr from xmlReadMemory -- same pattern this repo
/// already established for its other untrusted-XML consumer (`DocGuard`,
/// server/core/src/saml_provider.cpp:855).
struct XmlDocGuard {
    xmlDocPtr d;
    explicit XmlDocGuard(xmlDocPtr doc) : d(doc) {}
    ~XmlDocGuard() { if (d) xmlFreeDoc(d); }
    XmlDocGuard(const XmlDocGuard&) = delete;
    XmlDocGuard& operator=(const XmlDocGuard&) = delete;
};

inline constexpr const char* kTaskSchedulerNamespaceUri =
    "http://schemas.microsoft.com/windows/2004/02/mit/task";

/// True when `n` sits in the Task Scheduler namespace this parser accepts at
/// the root. Genuine `IRegisteredTask::get_Xml()` output uses exactly one
/// default namespace for every element, so this is always true for real
/// input; the check exists as a hardening layer against a document whose
/// root passes the namespace check but whose descendants redeclare a
/// foreign default namespace (schema-garbage that merely happens to share
/// child tag names like `<Settings>`/`<Actions>`) -- without it, such a
/// descendant would be silently interpreted as a genuine task element.
inline bool in_task_scheduler_ns(xmlNodePtr n) {
    return n && n->ns && n->ns->href && xmlStrEqual(n->ns->href, BAD_CAST kTaskSchedulerNamespaceUri);
}

/// First direct-child element matching `local` by local name AND namespace
/// (`in_task_scheduler_ns`) -- see that function's comment for why the
/// namespace check matters despite genuine Task Scheduler XML using exactly
/// one namespace throughout.
inline xmlNodePtr xml_find_child(xmlNodePtr parent, const char* local) {
    if (!parent) return nullptr;
    for (xmlNodePtr n = xmlFirstElementChild(parent); n; n = xmlNextElementSibling(n)) {
        if (n->type == XML_ELEMENT_NODE && n->name && xmlStrEqual(n->name, BAD_CAST local) &&
            in_task_scheduler_ns(n))
            return n;
    }
    return nullptr;
}

inline std::string xml_get_text(xmlNodePtr node) {
    if (!node) return {};
    xmlChar* c = xmlNodeGetContent(node);
    if (!c) return {};
    // xmlNodeGetContent hands back a heap buffer only xmlFree may release.
    // Wrap it in a move-only RAII guard BEFORE the std::string construction
    // below -- that construction can throw (bad_alloc) on a large node, and
    // a manual xmlFree() call placed after it (as this function previously
    // did) would never run on that path, leaking the buffer. Same idiom
    // this repo already established for libxml2 output buffers elsewhere
    // (tests/unit/server/test_saml_provider.cpp's XmlStrGuard).
    const std::unique_ptr<xmlChar, void (*)(void*)> guard{c, xmlFree};
    return std::string(reinterpret_cast<const char*>(c));
}

} // namespace detail

/// Parses a real `IRegisteredTask::get_Xml()` document via libxml2 -- a real
/// parser handles self-closing elements, attributes (including a quoted
/// value containing `>` or `/>`), and entity decoding correctly BY
/// CONSTRUCTION, closing an entire class of defects a hand-rolled
/// find()-based scanner kept missing one shape at a time across several
/// rounds of adversarial review (this file's prior implementation).
///
/// Same XXE-safe posture this repo already established for its other
/// untrusted-XML consumer (server/core/src/saml_provider.cpp:846-863):
/// `XML_PARSE_NONET` blocks external-entity network fetches,
/// `XML_PARSE_NOENT` is deliberately absent (entities aren't expanded
/// beyond the 5 predefined ones libxml2 always decodes), and a
/// DOCTYPE/DTD is explicitly rejected rather than trusted. A parse failure,
/// a rejected DTD, or a missing/wrong root leaves TaskInfo at its
/// documented defaults -- this is still best-effort over possibly-truncated
/// XML, not a validating parser; it just validates well-formedness instead
/// of hand-scanning for it.
///
/// Bounded twice against an adversarial or corrupt document (#4184): an
/// explicit `kMaxTaskXmlBytes` cap rejects an oversized document before
/// `xmlReadMemory` ever sees it (also closing the `size_t` -> `int` length
/// narrowing that call requires -- unreachable in practice once the byte cap
/// is well under INT_MAX, but guarded explicitly rather than relying on that
/// incidentally). Depth is NOT explicitly capped here: `XML_PARSE_HUGE` is
/// deliberately never passed, so libxml2's own default ~256-level parser
/// depth ceiling applies and a document nested deeper than that fails the
/// parse cleanly (a real error, not a crash or unbounded resource use) --
/// this function relies on that built-in ceiling rather than re-implementing
/// its own depth tracking over the resulting tree.
///
/// The expected root is validated by BOTH local name (`Task`) and namespace
/// URI (Task Scheduler's one documented default namespace) -- a document
/// using unrelated element names that merely happen to share `<Settings>`/
/// `<Actions>`/`<Triggers>` tags under some other root or namespace no
/// longer parses as a plausible task with no signal it came from elsewhere.
///
/// `xml` is ALWAYS real UTF-8 bytes by the time it reaches this function --
/// the caller (autoruns_win.cpp) converts the raw `IRegisteredTask::get_Xml()`
/// BSTR via wstring_to_utf8 first. The XML prolog's OWN `encoding=` attribute
/// is stale after that conversion (`get_Xml()` commonly returns
/// `encoding="UTF-16"`, since the BSTR itself was UTF-16 -- the declaration
/// describes the ORIGINAL wire form, not what this function actually
/// receives). A real parser given `encoding=nullptr` trusts that declaration
/// and would misinterpret genuinely-UTF-8 bytes as UTF-16 -- passing "UTF-8"
/// explicitly here overrides it with the encoding this call site actually
/// guarantees, rather than trusting a label the upstream conversion already
/// invalidated.
inline constexpr std::size_t kMaxTaskXmlBytes = 1 << 20; // 1 MiB, same cap
                                                          // and reasoning as
                                                          // saml_provider.cpp's
                                                          // XML size guard.

inline TaskInfo parse_task_xml(std::string_view xml) {
    TaskInfo out;
    if (xml.empty()) {
        out.reject = TaskReject::empty;
        return out; // nothing to parse -- parsed_ok stays false
    }
    if (xml.size() > kMaxTaskXmlBytes ||
        xml.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        out.reject = TaskReject::oversized;
        return out; // refuse before xmlReadMemory ever sees it -- also
                    // closes the size_t -> int length narrowing below
    }

    xmlDocPtr doc = xmlReadMemory(xml.data(), static_cast<int>(xml.size()), "task.xml", "UTF-8",
                                  XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    if (!doc) {
        out.reject = TaskReject::malformed;
        return out; // genuine parse failure -- parsed_ok stays false
    }
    detail::XmlDocGuard guard{doc};
    if (doc->intSubset || doc->extSubset) {
        out.reject = TaskReject::dtd;
        return out; // DOCTYPE/DTD present -- malformed
    }

    xmlNodePtr root = xmlDocGetRootElement(doc);
    // The expected task-XML root is exactly <Task> in the Task Scheduler
    // namespace -- a missing root, an unexpected element name, OR the right
    // element name under an unrelated/absent namespace (schema-garbage that
    // merely happens to share child tag names like <Settings>/<Actions>) is
    // ALSO a genuine parse failure from this function's point of view, not
    // merely "a task with nothing interesting in it" (#4184).
    if (!root || !root->name || !xmlStrEqual(root->name, BAD_CAST "Task")) {
        out.reject = TaskReject::wrong_root;
        return out;
    }
    if (!detail::in_task_scheduler_ns(root)) {
        out.reject = TaskReject::wrong_root;
        return out;
    }

    // From here on the document is well-formed AND <Task>-rooted -- every
    // early return below this point is a legitimate "this task has no X",
    // never a parse failure, so parsed_ok is set now rather than at the
    // very end (where a later restructure could accidentally skip it).
    out.parsed_ok = true;

    if (xmlNodePtr reg_info = detail::xml_find_child(root, "RegistrationInfo")) {
        if (xmlNodePtr date = detail::xml_find_child(reg_info, "Date"))
            out.registration_date = detail::xml_get_text(date);
    }

    // <Settings>/<Enabled> is the task-level enabled flag's real schema
    // location -- <Triggers> (which can carry its OWN per-trigger <Enabled>
    // children) appears earlier in document order than <Settings> in a real
    // capture, so a document-wide "first <Enabled> anywhere" search (this
    // function's pre-libxml2 form) could read a trigger's own Enabled value
    // as the task's. Scoping to the real parent element removes that
    // ambiguity entirely rather than papering over it.
    if (xmlNodePtr settings = detail::xml_find_child(root, "Settings")) {
        if (xmlNodePtr enabled = detail::xml_find_child(settings, "Enabled"))
            out.enabled = !detail::xsd_boolean_is_false(detail::xml_get_text(enabled));
    }
    // <Principals>/<Principal>/<UserId> -- likewise the real schema location,
    // not a document-wide first match.
    if (xmlNodePtr principals = detail::xml_find_child(root, "Principals")) {
        if (xmlNodePtr principal = detail::xml_find_child(principals, "Principal")) {
            if (xmlNodePtr user_id = detail::xml_find_child(principal, "UserId"))
                out.user_id = detail::xml_get_text(user_id);
        }
    }

    if (xmlNodePtr actions = detail::xml_find_child(root, "Actions")) {
        for (xmlNodePtr child = xmlFirstElementChild(actions); child;
             child = xmlNextElementSibling(child)) {
            if (child->type != XML_ELEMENT_NODE || !child->name) continue;
            if (!detail::in_task_scheduler_ns(child)) continue;
            if (xmlStrEqual(child->name, BAD_CAST "Exec")) {
                TaskAction action;
                action.command = detail::xml_get_text(detail::xml_find_child(child, "Command"));
                action.arguments =
                    detail::xml_get_text(detail::xml_find_child(child, "Arguments"));
                out.actions.push_back(std::move(action));
            } else if (xmlStrEqual(child->name, BAD_CAST "ComHandler") ||
                       xmlStrEqual(child->name, BAD_CAST "SendEmail") ||
                       xmlStrEqual(child->name, BAD_CAST "ShowMessage")) {
                // A sibling action element this leg doesn't decode -- ComHandler
                // (COM object invocation), SendEmail and ShowMessage (both
                // deprecated by Task Scheduler but still schema-legal) -- means
                // the task does more than the Exec rows above show.
                out.has_unmodelled_action = true;
            }
        }
    }

    if (xmlNodePtr triggers = detail::xml_find_child(root, "Triggers")) {
        // Every trigger element type ITriggerCollection can hold (Task
        // Scheduler's fixed schema). Each trigger's OWN direct <Enabled>
        // child decides that trigger alone (absent -> schema-default
        // enabled, false-per-xsd:boolean -> disabled) -- never aggregated
        // document-wide, or one disabled sibling would cancel out an
        // unrelated enabled (or untagged) trigger with no relationship to
        // it. A real element tree makes self-closed and Id-attributed
        // triggers ordinary children -- nothing extra needed to see them.
        static constexpr std::array<const char*, 9> kTriggerTags{
            "BootTrigger", "IdleTrigger", "LogonTrigger", "TimeTrigger", "EventTrigger",
            "SessionStateChangeTrigger", "CalendarTrigger", "RegistrationTrigger",
            "WnfStateChangeTrigger"};
        for (xmlNodePtr trigger = xmlFirstElementChild(triggers); trigger && !out.has_triggers;
             trigger = xmlNextElementSibling(trigger)) {
            if (trigger->type != XML_ELEMENT_NODE || !trigger->name) continue;
            if (!detail::in_task_scheduler_ns(trigger)) continue;
            bool is_known_trigger_type = false;
            for (const char* tag : kTriggerTags) {
                if (xmlStrEqual(trigger->name, BAD_CAST tag)) {
                    is_known_trigger_type = true;
                    break;
                }
            }
            if (!is_known_trigger_type) continue;
            xmlNodePtr enabled_node = detail::xml_find_child(trigger, "Enabled");
            if (!enabled_node || !detail::xsd_boolean_is_false(detail::xml_get_text(enabled_node)))
                out.has_triggers = true;
        }
    }
    return out;
}

/// Builds the win_scheduled_tasks row(s) for ONE already-parsed task -- pure,
/// extracted out of the win.cpp COM call site so this leg's actual row-
/// shaping logic (which action becomes which row, the multi-action
/// "[action N]" entry suffix, how a task with zero decoded actions --
/// whether genuinely action-less or carrying only an unmodelled action type
/// like <ComHandler> -- still emits exactly one row rather than silently
/// vanishing, #4184 AC1) is unit-testable on every build host, not just
/// verified by reading COM code that only compiles on Windows. The caller
/// (autoruns_win.cpp) still owns the row-count cap: it iterates the
/// returned vector itself, re-checking the cap per row exactly as it did
/// when this logic was inline.
inline std::vector<Row> rows_for_task(const TaskInfo& info, std::string_view location,
                                      std::string_view entry_base, std::string_view user,
                                      std::int64_t mtime, Enabled enabled_state) {
    std::vector<Row> rows;
    const bool multi = info.actions.size() > 1;
    if (info.actions.empty()) {
        // Zero decoded actions -- either a genuinely action-less task, or
        // one whose only action(s) are a type this scanner doesn't decode
        // (has_unmodelled_action; the caller separately notes a
        // "unmodelled_action_type" constraint for that case). Either way
        // the task itself is real and must still surface as one row, with
        // an empty target/args rather than being silently dropped.
        Row row;
        row.source_id = SourceId::win_scheduled_tasks;
        row.catalog_version = kAutorunSourceCatalogVersion;
        row.location = std::string{location};
        row.entry = std::string{entry_base};
        row.enabled = enabled_state;
        row.scope = Scope::system;
        row.user = std::string{user};
        row.signed_state = Signed::not_checked;
        row.mtime = mtime;
        rows.push_back(std::move(row));
        return rows;
    }
    for (std::size_t i = 0; i < info.actions.size(); ++i) {
        Row row;
        row.source_id = SourceId::win_scheduled_tasks;
        row.catalog_version = kAutorunSourceCatalogVersion;
        row.location = std::string{location};
        row.entry = multi ? std::string{entry_base} + " [action " + std::to_string(i + 1) + "]"
                          : std::string{entry_base};
        row.target = info.actions[i].command;
        row.args = info.actions[i].arguments;
        row.enabled = enabled_state;
        row.scope = Scope::system;
        row.user = std::string{user};
        row.signed_state = Signed::not_checked;
        row.mtime = mtime;
        rows.push_back(std::move(row));
    }
    return rows;
}

/// The Enabled decision for a `win_scheduled_tasks` row -- pulled out of
/// the win.cpp COM call site as a pure function so it stays testable on
/// every build host (the COM code itself only compiles on Windows).
///
/// The `ITaskFolder`/`IRegisteredTask::get_Enabled` COM property alone
/// overstates reach: a task with an empty `<Triggers/>` block is
/// `Enabled==true` yet Task Scheduler will never invoke it on its own --
/// only a manual Run counts, which is not persistence. Both the COM
/// property AND a genuine parsed trigger must hold for `enabled`. If
/// either COM accessor needed for that decision failed (`enabled_hr_ok`/
/// `xml_hr_ok` false), OR the XML that WAS retrieved didn't genuinely
/// parse (`info.parsed_ok` false -- a real parse failure, never conflated
/// with "well-formed but boring": see TaskInfo::parsed_ok), the state is
/// `unknown`, never a fabricated definite answer -- `get_Enabled` failing
/// leaves the caller's own `enabled_b` at its `VARIANT_TRUE` initializer
/// (would silently read as "enabled"), and a parse failure leaves
/// `info.has_triggers` at its default `false` (would silently read as
/// "disabled" for a task whose real trigger state was never actually
/// determined).
inline Enabled scheduled_task_enabled_state(bool enabled_hr_ok, bool xml_hr_ok, bool com_enabled,
                                            const TaskInfo& info) {
    if (!enabled_hr_ok || !xml_hr_ok || !info.parsed_ok) return Enabled::unknown;
    return (com_enabled && info.has_triggers) ? Enabled::enabled : Enabled::disabled;
}

// ── 8. parse_wmi_subscription_triple ─────────────────────────────────────

// The highest-value payload this plugin can produce
// (ActiveScriptEventConsumer::ScriptText) is routinely multi-line real
// script text; parse_wmi_subscription_triple splits on blank lines and
// requires exactly one "Key : Value" per line, so an unescaped embedded
// '\n' would either truncate the value to its first line or split one
// record into two. escape_wmi_value/format_wmi_block are the producer half
// of that round trip, kept in this portable seam (not autoruns_win.cpp,
// their only real caller) specifically so a test here can assert
// parse(format(original)) recovers the INTERIOR content and every embedded
// \\/\n/\r byte-for-byte, rather than only exercising the decoder against a
// hand-escaped literal. NOT a full identity round trip: the parser's own
// detail::trim strips leading/trailing whitespace from every "Key : Value"
// line before this function's unescaping ever runs, so a value with
// leading/trailing whitespace loses it -- forensic-fidelity loss only, the
// row and its interior content stay visible.
inline std::string escape_wmi_value(std::string_view v) {
    std::string out;
    out.reserve(v.size());
    for (char c : v) {
        if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else out += c;
    }
    return out;
}

inline std::string format_wmi_block(std::string_view cim_class,
                                    const std::map<std::string, std::string>& row) {
    std::string out = "CimClass : ";
    out += cim_class;
    out += '\n';
    for (const auto& [k, v] : row) {
        out += k;
        out += " : ";
        out += escape_wmi_value(v);
        out += '\n';
    }
    out += '\n';
    return out;
}

struct WmiTriple {
    bool filter_found = false;
    bool consumer_found = false;
    bool binding_found = false;
    std::string filter_name;
    std::string query;
    std::string consumer_name;
    std::string target; // first of CommandLineTemplate | ScriptText | ExecutablePath present
};

namespace detail {

using KvBlock = std::vector<std::pair<std::string, std::string>>;

inline std::string trim(std::string_view s) {
    std::size_t b = s.find_first_not_of(" \t");
    if (b == std::string_view::npos) return {};
    std::size_t e = s.find_last_not_of(" \t");
    return std::string{s.substr(b, e - b + 1)};
}

inline std::string kv_get(const KvBlock& block, std::string_view key) {
    for (const auto& [k, v] : block)
        if (k == key) return v;
    return {};
}

/// Inverse of autoruns_win.cpp's escape_wmi_value -- undoes the \\, \n, \r
/// escaping that keeps a multi-line value (e.g. ActiveScriptEventConsumer::
/// ScriptText) intact through this format's one-line-per-value shape.
inline std::string unescape_wmi_value(std::string_view v) {
    std::string out;
    out.reserve(v.size());
    for (std::size_t i = 0; i < v.size(); ++i) {
        if (v[i] == '\\' && i + 1 < v.size()) {
            const char next = v[i + 1];
            if (next == 'n') { out += '\n'; ++i; continue; }
            if (next == 'r') { out += '\r'; ++i; continue; }
            if (next == '\\') { out += '\\'; ++i; continue; }
        }
        out += v[i];
    }
    return out;
}

} // namespace detail

/// Parses PowerShell `Format-List`-style output (`Key : Value` lines, blocks
/// separated by blank lines) -- the shape `Get-CimInstance | Format-List`
/// produces for `__EventFilter` / an event-consumer class /
/// `__FilterToConsumerBinding`, which is A1's real capture format for this
/// source. Blocks are distinguished by their own `CimClass` value rather than
/// position, since a real capture may order Filter/Consumer/Binding blocks
/// arbitrarily. `target` tries three known consumer fields in the documented
/// priority order; a subscription whose consumer is a built-in type carrying
/// none of them (this plugin's own real capture: an `NTEventLogEventConsumer`
/// forwarding to the event log, not executing anything) leaves `target` empty
/// -- there is genuinely nothing to run, not a parse failure.
inline WmiTriple parse_wmi_subscription_triple(std::string_view text) {
    std::vector<detail::KvBlock> blocks;
    detail::KvBlock current;
    std::size_t pos = 0;
    auto flush = [&] {
        if (!current.empty()) blocks.push_back(std::move(current));
        current.clear();
    };
    while (pos <= text.size()) {
        std::size_t nl = text.find('\n', pos);
        std::string_view line = nl == std::string_view::npos ? text.substr(pos) : text.substr(pos, nl - pos);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        if (detail::trim(line).empty()) {
            flush();
        } else {
            std::size_t colon = line.find(':');
            if (colon != std::string_view::npos) {
                std::string key = detail::trim(line.substr(0, colon));
                std::string val = detail::unescape_wmi_value(detail::trim(line.substr(colon + 1)));
                if (!key.empty()) current.emplace_back(std::move(key), std::move(val));
            }
        }
        if (nl == std::string_view::npos) break;
        pos = nl + 1;
    }
    flush();

    WmiTriple out;
    for (const auto& block : blocks) {
        std::string cim_class = detail::kv_get(block, "CimClass");
        if (cim_class.find("__EventFilter") != std::string::npos) {
            out.filter_found = true;
            out.filter_name = detail::kv_get(block, "Name");
            out.query = detail::kv_get(block, "Query");
        } else if (cim_class.find("__FilterToConsumerBinding") != std::string::npos) {
            out.binding_found = true;
        } else if (cim_class.find("Consumer") != std::string::npos) {
            out.consumer_found = true;
            out.consumer_name = detail::kv_get(block, "Name");
            for (const char* field : {"CommandLineTemplate", "ScriptText", "ExecutablePath"}) {
                std::string v = detail::kv_get(block, field);
                if (!v.empty()) { out.target = v; break; }
            }
        }
    }
    return out;
}

// ── 9. parse_crontab ──────────────────────────────────────────────────────

struct CronEntry {
    std::string schedule; // the 5 schedule fields, space-joined
    std::string user;     // "-" for a user crontab (no user field)
    std::string command;
};

struct CrontabParseResult {
    std::vector<CronEntry> entries;
    int rejected_lines = 0;
};

namespace detail {

inline std::vector<std::string_view> split_ws(std::string_view line, std::size_t max_tokens) {
    std::vector<std::string_view> out;
    std::size_t pos = 0;
    while (pos < line.size() && out.size() + 1 < max_tokens) {
        while (pos < line.size() && (line[pos] == ' ' || line[pos] == '\t')) ++pos;
        std::size_t start = pos;
        while (pos < line.size() && line[pos] != ' ' && line[pos] != '\t') ++pos;
        if (pos > start) out.push_back(line.substr(start, pos - start));
        else break;
    }
    while (pos < line.size() && (line[pos] == ' ' || line[pos] == '\t')) ++pos;
    if (pos < line.size()) out.push_back(line.substr(pos));
    return out;
}

inline bool is_comment_or_blank_or_assignment(std::string_view line) {
    std::size_t nb = line.find_first_not_of(" \t");
    if (nb == std::string_view::npos) return true;
    if (line[nb] == '#') return true;
    // VAR = VALUE (crontab(5) environment-variable assignment): an
    // identifier ([A-Za-z_][A-Za-z0-9_]*), optional surrounding
    // whitespace, then '='. crontab(5) permits whitespace on either side
    // of the '=' -- "MAILTO=root", "MAILTO = root", "MAILTO= root", and
    // "MAILTO =root" are ALL valid assignments and must be skipped here,
    // never misparsed as a malformed cron command line just because the
    // no-space form was the only one this used to recognize.
    std::size_t p = nb;
    if (!(std::isalpha(static_cast<unsigned char>(line[p])) != 0 || line[p] == '_')) return false;
    ++p;
    while (p < line.size() &&
          (std::isalnum(static_cast<unsigned char>(line[p])) != 0 || line[p] == '_'))
        ++p;
    while (p < line.size() && (line[p] == ' ' || line[p] == '\t')) ++p;
    return p < line.size() && line[p] == '=';
}

// crontab(5) nickname shortcuts -- each replaces the 5 schedule fields with
// a single leading token, so a line using one tokenizes far shorter than
// the 5-field form and must be recognized before the field-count check.
inline bool is_cron_nickname(std::string_view token) {
    static constexpr std::string_view kNicknames[] = {
        "@reboot", "@yearly", "@annually", "@monthly",
        "@weekly", "@daily",  "@midnight", "@hourly",
    };
    for (auto n : kNicknames) {
        if (token == n) return true;
    }
    return false;
}

} // namespace detail

/// Parses crontab(5) text. `system_format` selects the 6-field shape
/// (5 schedule fields + a user field, `/etc/crontab` and `/etc/cron.d/*`) vs
/// the 5-field per-user shape (no user field). A line with fewer fields than
/// its format requires is REJECTED AND COUNTED, never silently dropped nor
/// guessed at -- `rejected_lines` is how a caller learns the input was
/// malformed rather than merely empty.
inline CrontabParseResult parse_crontab(std::string_view text, bool system_format) {
    CrontabParseResult result;
    const std::size_t required = system_format ? 7 : 6; // 5 schedule + [user] + command
    std::size_t pos = 0;
    while (pos <= text.size()) {
        std::size_t nl = text.find('\n', pos);
        std::string_view line = nl == std::string_view::npos ? text.substr(pos) : text.substr(pos, nl - pos);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        if (detail::is_comment_or_blank_or_assignment(line)) {
            if (nl == std::string_view::npos) break;
            pos = nl + 1;
            continue;
        }
        auto tokens = detail::split_ws(line, required);
        if (!tokens.empty() && detail::is_cron_nickname(tokens[0])) {
            // Nickname form: "@reboot [user] command" -- 2 fields (per-user)
            // or 3 (system), never the 5-field schedule shape.
            const std::size_t nick_required = system_format ? 3 : 2;
            auto nick_tokens = detail::split_ws(line, nick_required);
            if (nick_tokens.size() < nick_required) {
                ++result.rejected_lines;
            } else {
                CronEntry e;
                e.schedule = std::string{nick_tokens[0]};
                std::size_t cmd_idx = 1;
                if (system_format) { e.user = std::string{nick_tokens[1]}; cmd_idx = 2; }
                else e.user = "-";
                e.command = std::string{nick_tokens[cmd_idx]};
                result.entries.push_back(std::move(e));
            }
        } else if (tokens.size() < required) {
            ++result.rejected_lines;
        } else {
            CronEntry e;
            e.schedule = std::string{tokens[0]} + ' ' + std::string{tokens[1]} + ' ' +
                        std::string{tokens[2]} + ' ' + std::string{tokens[3]} + ' ' +
                        std::string{tokens[4]};
            std::size_t cmd_idx = 5;
            if (system_format) { e.user = std::string{tokens[5]}; cmd_idx = 6; }
            else e.user = "-";
            e.command = std::string{tokens[cmd_idx]};
            result.entries.push_back(std::move(e));
        }
        if (nl == std::string_view::npos) break;
        pos = nl + 1;
    }
    return result;
}

// ── 10. parse_anacrontab ──────────────────────────────────────────────────

struct AnacronEntry {
    std::string period;   // days, or an @-shorthand (@monthly, @weekly...)
    std::string delay;    // minutes
    std::string job_id;
    std::string command;
};

struct AnacrontabParseResult {
    std::vector<AnacronEntry> entries;
    int rejected_lines = 0; // a non-comment/blank/assignment line with != 4
                            // fields -- REJECTED AND COUNTED, never silently
                            // dropped, mirroring CrontabParseResult's
                            // identical contract (see parse_crontab's own
                            // banner).
};

/// anacrontab(5): `period  delay  job-identifier  command`. Comments, blank
/// lines and VAR=VALUE lines (SHELL=, HOME=, LOGNAME=) are skipped exactly
/// like crontab(5)'s.
inline AnacrontabParseResult parse_anacrontab(std::string_view text) {
    AnacrontabParseResult result;
    std::size_t pos = 0;
    while (pos <= text.size()) {
        std::size_t nl = text.find('\n', pos);
        std::string_view line = nl == std::string_view::npos ? text.substr(pos) : text.substr(pos, nl - pos);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        if (!detail::is_comment_or_blank_or_assignment(line)) {
            auto tokens = detail::split_ws(line, 4);
            if (tokens.size() == 4) {
                result.entries.push_back(AnacronEntry{std::string{tokens[0]}, std::string{tokens[1]},
                                                       std::string{tokens[2]}, std::string{tokens[3]}});
            } else {
                ++result.rejected_lines;
            }
        }
        if (nl == std::string_view::npos) break;
        pos = nl + 1;
    }
    return result;
}

// ── 11. parse_systemd_timer / timer_enabled_from_wants ───────────────────

struct SystemdTimerFields {
    std::string on_calendar;
    std::string on_boot_sec;
    std::string on_active_sec; // OnUnitActiveSec
    std::string unit;          // explicit Unit= override; often absent
    std::string wanted_by;
};

/// Minimal INI-section reader over a systemd unit file: tracks the current
/// `[Section]` and reads `Key=Value` lines only from `[Timer]` (OnCalendar,
/// OnBootSec, OnUnitActiveSec, Unit) and `[Install]` (WantedBy).
inline SystemdTimerFields parse_systemd_timer(std::string_view text) {
    SystemdTimerFields out;
    std::string section;
    std::size_t pos = 0;
    while (pos <= text.size()) {
        std::size_t nl = text.find('\n', pos);
        std::string_view line = nl == std::string_view::npos ? text.substr(pos) : text.substr(pos, nl - pos);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        std::string_view trimmed = line;
        std::size_t nb = trimmed.find_first_not_of(" \t");
        trimmed = nb == std::string_view::npos ? std::string_view{} : trimmed.substr(nb);
        if (!trimmed.empty() && trimmed.front() == '[' && trimmed.back() == ']') {
            section = std::string{trimmed.substr(1, trimmed.size() - 2)};
        } else if (!trimmed.empty() && trimmed.front() != '#' && trimmed.front() != ';') {
            std::size_t eq = trimmed.find('=');
            if (eq != std::string_view::npos) {
                // systemd.syntax(7): whitespace around '=' is ignorable --
                // "OnCalendar = daily" is equivalent to "OnCalendar=daily",
                // not a different (unrecognized, silently dropped) key.
                std::string key = detail::trim(trimmed.substr(0, eq));
                std::string val = detail::trim(trimmed.substr(eq + 1));
                if (section == "Timer") {
                    if (key == "OnCalendar") out.on_calendar = val;
                    else if (key == "OnBootSec") out.on_boot_sec = val;
                    else if (key == "OnUnitActiveSec") out.on_active_sec = val;
                    else if (key == "Unit") out.unit = val;
                } else if (section == "Install" && key == "WantedBy") {
                    out.wanted_by = val;
                }
            }
        }
        if (nl == std::string_view::npos) break;
        pos = nl + 1;
    }
    return out;
}

/// A timer is enabled iff its unit file is symlinked into the matching
/// `<target>.wants/` directory -- `wants_dir_listing` is that directory's
/// `ls -l` text and `timer_filename` the unit's own filename (e.g.
/// `apt-daily.timer`), matched as a whole path component so a name that is
/// merely a substring of another (`apt-daily.timer` vs
/// `apt-daily-upgrade.timer`) cannot false-positive.
inline bool timer_enabled_from_wants(std::string_view wants_dir_listing,
                                     std::string_view timer_filename) {
    std::size_t pos = 0;
    while (pos <= wants_dir_listing.size()) {
        std::size_t nl = wants_dir_listing.find('\n', pos);
        std::string_view line = nl == std::string_view::npos ? wants_dir_listing.substr(pos)
                                                              : wants_dir_listing.substr(pos, nl - pos);
        std::size_t arrow = line.find(" -> ");
        std::string_view name_field = arrow == std::string_view::npos ? line : line.substr(0, arrow);
        std::size_t last_space = name_field.find_last_of(' ');
        std::string_view name = last_space == std::string_view::npos ? name_field
                                                                     : name_field.substr(last_space + 1);
        if (name == timer_filename) return true;
        if (nl == std::string_view::npos) break;
        pos = nl + 1;
    }
    return false;
}

// ── 12. parse_desktop_entry ───────────────────────────────────────────────

struct DesktopEntry {
    std::string exec;
    bool hidden = false;
    std::string only_show_in;
    std::string not_show_in;
    bool gnome_autostart_enabled_present = false;
    bool gnome_autostart_enabled = true;
    // `DBusActivatable=true` per the Desktop Entry spec: the launch
    // mechanism is D-Bus service activation, not `Exec` -- the spec
    // requires `Exec` only when this is NOT true.
    bool dbus_activatable = false;
    Enabled enabled = Enabled::enabled;
    // True when this file has no `[Desktop Entry]` group at all, or that
    // group has no (or an empty) `Exec` key AND is not `DBusActivatable` --
    // there is nothing this leg can actually run or name, so a caller must
    // not report a plain `enabled` row with an empty target as if it found
    // a real autostart entry.
    bool malformed = false;
};

/// Parses the `[Desktop Entry]` group of a `.desktop` file (XDG Desktop Entry
/// spec). `enabled` is `disabled` when `Hidden=true` OR
/// `X-GNOME-Autostart-enabled=false` -- either alone is sufficient, matching
/// the two independent ways a DE hides an autostart entry without deleting
/// the file.
inline DesktopEntry parse_desktop_entry(std::string_view text) {
    DesktopEntry out;
    bool in_group = false;
    bool group_seen = false;
    std::size_t pos = 0;
    while (pos <= text.size()) {
        std::size_t nl = text.find('\n', pos);
        std::string_view line = nl == std::string_view::npos ? text.substr(pos) : text.substr(pos, nl - pos);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        if (!line.empty() && line.front() == '[') {
            in_group = (line == "[Desktop Entry]");
            if (in_group) group_seen = true;
        } else if (in_group) {
            std::size_t eq = line.find('=');
            if (eq != std::string_view::npos) {
                // XDG Desktop Entry spec: whitespace around '=' is
                // ignorable, matching parse_systemd_timer's identical fix.
                const std::string key = detail::trim(line.substr(0, eq));
                const std::string val = detail::trim(line.substr(eq + 1));
                if (key == "Exec") out.exec = val;
                else if (key == "Hidden") out.hidden = (val == "true");
                else if (key == "OnlyShowIn") out.only_show_in = val;
                else if (key == "NotShowIn") out.not_show_in = val;
                else if (key == "X-GNOME-Autostart-enabled") {
                    out.gnome_autostart_enabled_present = true;
                    out.gnome_autostart_enabled = (val == "true");
                }
                else if (key == "DBusActivatable") out.dbus_activatable = (val == "true");
            }
        }
        if (nl == std::string_view::npos) break;
        pos = nl + 1;
    }
    out.enabled = (out.hidden || (out.gnome_autostart_enabled_present && !out.gnome_autostart_enabled))
                     ? Enabled::disabled
                     : Enabled::enabled;
    out.malformed = !group_seen || (out.exec.empty() && !out.dbus_activatable);
    return out;
}

// ── 13. LaunchdFields / launchd_row_from_fields ──────────────────────────

/// The fields a launchd plist read (CFPropertyListCreateWithData, P14's
/// concern) needs to hand this pure layer. `program` is the plist's own
/// `Program` key when present; when absent, launchd itself falls back to
/// `ProgramArguments[0]` as the executable, and `launchd_row_from_fields`
/// follows that same documented fallback.
struct LaunchdFields {
    std::string label;
    std::string program; // may be empty -- fall back to program_arguments[0]
    std::vector<std::string> program_arguments;
    bool disabled_present = false;
    bool disabled_value = false;
};

/// Builds a Row from already-extracted plist fields plus the OS-known
/// context (which source this came from, the plist's own path, and whether
/// it is a system or user location). `enabled` is `enabled` when `Disabled`
/// is absent -- launchd's own documented default -- and only `unknown` if
/// this function is ever called with no way to reason about it (it always
/// can, so this branch does not occur; kept for symmetry with other row
/// builders that DO have a genuine unknown case).
inline Row launchd_row_from_fields(SourceId source_id, const LaunchdFields& fields,
                                   std::string_view plist_path, Scope scope,
                                   std::int64_t mtime) {
    Row row;
    row.source_id = source_id;
    row.catalog_version = kAutorunSourceCatalogVersion;
    row.location = std::string{plist_path};
    row.entry = fields.label;
    if (!fields.program.empty()) {
        row.target = fields.program;
        // ProgramArguments[0] conventionally duplicates Program itself (it is
        // what launchd execs argv[0] as); the REAL extra arguments start at
        // index 1. Skip index 0 here so `args` does not repeat the target.
        std::string joined;
        for (std::size_t i = 1; i < fields.program_arguments.size(); ++i) {
            if (i > 1) joined += ' ';
            joined += fields.program_arguments[i];
        }
        row.args = joined;
    } else if (!fields.program_arguments.empty()) {
        row.target = fields.program_arguments.front();
        std::string joined;
        for (std::size_t i = 1; i < fields.program_arguments.size(); ++i) {
            if (i > 1) joined += ' ';
            joined += fields.program_arguments[i];
        }
        row.args = joined;
    }
    row.enabled = fields.disabled_present ? (fields.disabled_value ? Enabled::disabled : Enabled::enabled)
                                          : Enabled::enabled;
    row.scope = scope;
    row.user = "-";
    row.signed_state = signed_from_path(plist_path);
    row.mtime = mtime;
    return row;
}

// ── 14. parse_periodic_dir_listing ────────────────────────────────────────

/// Parses `ls -l`-style text and returns each entry's filename (the last
/// whitespace-separated field), skipping the `total N` header line. Used for
/// `/etc/periodic/{daily,weekly,monthly}` script directories.
inline std::vector<std::string> parse_periodic_dir_listing(std::string_view ls_output) {
    std::vector<std::string> out;
    std::size_t pos = 0;
    while (pos <= ls_output.size()) {
        std::size_t nl = ls_output.find('\n', pos);
        std::string_view line = nl == std::string_view::npos ? ls_output.substr(pos)
                                                              : ls_output.substr(pos, nl - pos);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        // A real `ls -l` entry line always opens with a file-type/permission
        // character (-, d, l, ...); this rejects both the `total N` header
        // and prose (e.g. a recorded "ABSENT: ..." note standing in for a
        // directory that does not exist on this host) that a naive
        // last-whitespace-token split would otherwise mistake for a listing.
        constexpr std::string_view kEntryLeadChars = "-dlbcps";
        if (!line.empty() && kEntryLeadChars.find(line.front()) != std::string_view::npos) {
            std::size_t last_space = line.find_last_of(' ');
            std::string_view name = last_space == std::string_view::npos ? line
                                                                         : line.substr(last_space + 1);
            if (!name.empty()) out.emplace_back(name);
        }
        if (nl == std::string_view::npos) break;
        pos = nl + 1;
    }
    return out;
}

// ── 15. parse_emond_rule_plist_fields ────────────────────────────────────

/// Mirrors LaunchdFields' shape: the caller (P14) extracts these from an
/// emond rule plist dict and this pure layer turns them into a Row.
struct EmondRuleFields {
    std::string name;
    bool enabled_present = false;
    bool enabled_value = true;
    std::string command;      // the rule's StartProgram/command path, if any
    std::vector<std::string> args;
};

inline Row parse_emond_rule_plist_fields(const EmondRuleFields& fields, std::string_view plist_path,
                                         std::int64_t mtime) {
    Row row;
    row.source_id = SourceId::mac_emond;
    row.catalog_version = kAutorunSourceCatalogVersion;
    row.location = std::string{plist_path};
    row.entry = fields.name;
    row.target = fields.command;
    std::string joined;
    for (std::size_t i = 0; i < fields.args.size(); ++i) {
        if (i) joined += ' ';
        joined += fields.args[i];
    }
    row.args = joined;
    row.enabled = fields.enabled_present ? (fields.enabled_value ? Enabled::enabled : Enabled::disabled)
                                         : Enabled::unknown;
    row.scope = Scope::system;
    row.user = "-";
    row.signed_state = signed_from_path(plist_path);
    row.mtime = mtime;
    return row;
}

} // namespace yuzu::autoruns
