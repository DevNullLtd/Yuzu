/**
 * local_security_policy_parsers.hpp -- pure core of the plugin: no OS call, process
 * or clock. Every decision (errno class, status, row shape) is a function here; the
 * leg TUs only read bytes and hand them in.
 *
 * Linux and macOS legs (password_policy, lockout_policy, audit_policy) ship in this PR.
 * The Windows leg and the `sudoers` action are PLANNED, follow as their own PR -- see
 * local_security_policy_legs.hpp's banner. Nothing in this file emits the `sudoers|...`
 * 7-field row or the Windows 2-field diagnostic row today.
 *
 * Rows (fields through safe_output_field):
 *   <action>|<key>|<value>|<source>          password_policy, lockout_policy, audit_policy
 *   <action>|status|<state>|<reason>         the zero-row fallback (local_security_policy_legs.hpp)
 *   constrained|<token>                      a contained exception (`internal_error`), or the
 *                                            planned-leg placeholder (local_security_policy_plugin.cpp)
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
/// rule): `secedit_export_complete` already compares section/key names case-insensitively,
/// but a plain `std::map<std::string,...>` orders and looks up by exact bytes, so a
/// differently-cased section or key that passed the completeness check was invisible to
/// `secedit_policy_rows`'s row lookups -- a present setting silently read as the legitimate
/// modal value `absent` (#4997). `is_transparent` lets `.find()` take a `std::string_view`
/// literal directly, same call sites as before. Values keep whatever casing the export
/// file used -- only lookup/ordering are case-insensitive, so the audit row loop below
/// (which prints the stored key verbatim) is unaffected.
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
/// unordered: secedit_policy_rows iterates `[Event Audit]` directly, so the key order IS
/// the audit_policy row order on the wire.
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

// ---- errno classification and status (one function for every leg) --------------------

inline constexpr int kReadOversized = -1;
inline constexpr int kReadNotRegular = -2;
/// The file holds a NUL byte. Every C consumer of these files (sudo's lexer, libpam,
/// shadow's getdef) stops or diverges at it, so no value read past it can be reported
/// as the one in force, and a NUL crossing write_output's C string would cut the row.
inline constexpr int kReadEmbeddedNul = -3;

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
inline std::string join_row(std::string_view head, std::initializer_list<std::string_view> fields) {
    std::string r{head};
    for (auto f : fields) {
        r += '|';
        r += yuzu::util::safe_output_field(f);
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

// ---- file-source collector (Linux and macOS file legs; reader injected) --------------------

struct FileRead {
    int err = 0; // 0 = ok; errno, or kReadOversized / kReadNotRegular / kReadEmbeddedNul
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
        if (rows.size() + 1 >= kMaxRows) {
            if (!capped) {
                acc.add_failure("row_cap");
                rows.push_back(truncation_marker());
            }
            capped = true;
            return;
        }
        rows.push_back(std::move(r));
    }

    std::string marker_prefix{"local_security_policy"};
    std::size_t marker_fields{4};
    // marker_fields is always 4 in this PR: the Sudoers action (whose row is 7 fields) is
    // PLANNED, follows as its own PR -- see local_security_policy_legs.hpp's "when the sudoers
    // action lands" note, which restores the 7-field branch here.
    [[nodiscard]] std::string truncation_marker() const {
        return format_kv_row(marker_prefix, "source_state", "unreadable:row_cap", marker_prefix);
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

// detail::sudoers_file is PLANNED, follows as its own PR (see local_security_policy_legs.hpp's
// "when the sudoers action lands" note) -- it called parse_sudoers/format_sudoers_row/
// SudoersEntry, all of which are absent from this PR's copy of the file.

} // namespace detail

/// Collects the rows + status for a file-backed action. `Macos` password/lockout
/// come from pwpolicy, not files, and are not handled here.
inline Collected collect_file_policy(FileFlavor flavor, LocalPolicyAction action,
                                     const FileReader& rd,
                                     [[maybe_unused]] const DirLister& ls) {
    // `ls` is unused in this PR: its only caller was the Sudoers case (sudoers.d
    // enumeration), PLANNED and stubbed above. Kept in the signature so linux.cpp/macos.cpp's
    // call sites need no change; PR4 restores its use.
    detail::Tally t;
    const auto prefix = action_row_prefix(action);
    t.marker_prefix = std::string{prefix};
    // FAIL CLOSED, not open. Every arm below is unreachable today -- execute()
    // rejects Unknown before any leg runs, and the macOS leg routes Password and
    // Lockout to pwpolicy before calling here -- but returning an empty Collected
    // would be status OK with zero rows, which apply_collected reports as a green
    // empty result. A named CONSTRAINED says what happened instead. (The
    // Password/Lockout arms read Linux paths and never consult `flavor`, so this
    // is also what stops a relaxed macOS early return quietly reading
    // /etc/login.defs on a Mac.)
    //
    // Sudoers is PLANNED, follows as its own PR (see local_security_policy_legs.hpp's "when
    // the sudoers action lands" note) -- refused here, same as Unknown, rather than reaching
    // the switch below, whose Sudoers case is a stub.
    if (action == LocalPolicyAction::Unknown || action == LocalPolicyAction::Sudoers ||
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
    case LocalPolicyAction::Sudoers:
        break; // refused above (PLANNED, follows as its own PR); the switch stays exhaustive
    case LocalPolicyAction::Unknown: break; // refused above; the switch stays exhaustive
    }
    return {std::move(t.rows), select_status(t.readable, t.denied, t.failed + (t.capped ? 1 : 0)),
            t.acc.reason()};
}

// ---- macOS pwpolicy ------------------------------------------------------------------------

struct PwPolicyItem {
    std::string category;   // policyCategoryAuthentication | policyCategoryPasswordContent | ...
    std::string identifier; // policyIdentifier
    std::string content;    // policyContent (Apple policy expression)
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
inline Collected pwpolicy_rows(LocalPolicyAction action, const std::vector<PwPolicyItem>& items) {
    const auto prefix = action_row_prefix(action);
    std::vector<std::string> rows;
    yuzu::shared::ConstraintAccumulator acc;
    for (const auto& it : items) {
        const bool lock = it.category.find("Authentication") != std::string::npos;
        const bool pw = it.category.rfind("policyCategoryPassword", 0) == 0;
        const std::string& named = it.identifier.empty() ? it.category : it.identifier;
        const std::string src = named.empty() ? std::string{"pwpolicy"} : "pwpolicy:" + named;
        const auto defect_rows = [&] {
            for (const auto& d : it.defects) {
                rows.push_back(format_kv_row(prefix, "source_state", "unreadable:" + d, src));
                acc.add_failure("pwpolicy:" + d);
            }
        };
        if (!lock && !pw) {
            // The root non_string_key placeholder has no category to name; a real
            // category -- even an empty-named one -- always keeps its row.
            if (!(it.category.empty() && !it.defects.empty()))
                rows.push_back(format_kv_row(prefix, "unmodelled_category", it.category, "pwpolicy"));
            defect_rows();
            continue;
        }
        if (lock != (action == LocalPolicyAction::Lockout)) continue;
        if (it.content.empty() && it.params.empty() && it.defects.empty()) {
            // A policy element carrying nothing this action can report is a shape defect,
            // not "no policy": without this row it would vanish, and could leave the clean
            // `policies|none` answer below.
            rows.push_back(format_kv_row(prefix, "source_state", "unreadable:missing_content", src));
            acc.add_failure("pwpolicy:missing_content");
            continue;
        }
        if (!it.content.empty()) rows.push_back(format_kv_row(prefix, "policy_content", it.content, src));
        if (const auto n = pwpolicy_min_length(it.content))
            rows.push_back(format_kv_row(prefix, "minimum_length", std::to_string(*n), src));
        for (const auto& [k, v] : it.params) {
            if (k.rfind("policyAttribute", 0) == 0) rows.push_back(format_kv_row(prefix, k, v, src));
            else rows.push_back(format_kv_row(prefix, "unmodelled_parameter", k + "=" + v, src));
        }
        defect_rows();
    }
    if (rows.empty()) rows.push_back(format_kv_row(prefix, "policies", "none", "pwpolicy"));
    return {std::move(rows), acc.any_failure() ? PolicyStatus::Constrained : PolicyStatus::Ok,
            acc.reason()};
}

} // namespace yuzu::local_security_policy
