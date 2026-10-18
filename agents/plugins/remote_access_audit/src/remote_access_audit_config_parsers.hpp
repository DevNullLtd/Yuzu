#pragma once

// remote_access_audit_config_parsers.hpp -- pure parsers and row formatters for the
// sshd_config half of the remote_access_audit plugin: what this host's sshd is CONFIGURED to
// accept, and whether its service is enabled. Header-only and portable; no file I/O, no
// subprocess, no OS header. The `status|list|...` row is NOT built here (the legs header owns it).
//
// Also owns what the keys half shares (row/byte limits, SourceState, wire_field, source_row);
// the keys header includes THIS one, never the reverse.
//
// PRIVACY CONTRACT: the AuthorizedKeysFile tokens are kept in SshdConfigState for path
// resolution only; the `authorizedkeysfile` row reports `default | none | custom:<n>`, never a path.
//
// Semantics verified against OpenSSH master: servconf.c process_server_config_line_depth,
// misc.c strdelim_internal/argv_split.

#include <row_byte_budget.hpp>
#include <wire_utf8.hpp>
#include <yuzu/string_utils.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <filesystem>
#include <functional>
#include <initializer_list>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::remote_access_audit {

enum class SourceState { read, absent, refused, failed };

/// One budget for EVERY row kind of a dispatch (source, config, service, file, key).
inline constexpr std::size_t kMaxRows = 2048;
inline constexpr std::size_t kMaxBytes = 1024 * 1024;
inline constexpr std::size_t kMaxFieldBytes = 4096;
/// Fixed per-row cost charged on top of the field bytes, so a flood of empty rows is bounded
/// by the byte budget as well as the row budget.
inline constexpr std::size_t kRowOverhead = 64;
inline constexpr std::size_t kMaxIncludeDepth = 4;
inline constexpr std::size_t kMaxIncludeFiles = 32;
inline constexpr std::size_t kMaxPorts = 256; ///< sshd's own MAX_PORTS
/// AuthorizedKeysFile tokens kept; the rest are dropped with a token. The order of the
/// MAX_AUTHKEYS_FILES (100) older OpenSSH enforced: each token is resolved once per account home.
inline constexpr std::size_t kMaxAuthorizedKeysFileTokens = 100;

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

inline std::string lower(std::string_view s) {
    std::string out(s);
    for (auto& c : out)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

/// misc.h WHITESPACE: " \t\r\n".
inline bool is_wsp(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

inline std::size_t skip_wsp(std::string_view s, std::size_t at) {
    while (at < s.size() && is_wsp(s[at]))
        ++at;
    return at;
}

} // namespace detail

/// One row field: NUL and invalid UTF-8 replaced, backslash/CR/LF/pipe made safe, cut at
/// kMaxFieldBytes (`oversized` records the cut), and an empty value spelled `-`.
inline std::string wire_field(std::string_view v, bool& oversized) {
    std::string s(v);
    if (s.size() > kMaxFieldBytes) {
        oversized = true;
        s.resize(kMaxFieldBytes);
    }
    yuzu::shared::scrub_wire_bytes(s);
    if (s.empty())
        return "-";
    return yuzu::util::safe_output_field(s);
}

/// `prefix|f1|f2|...` with every field through wire_field (the identity on the lowercase-ASCII
/// literals, digits and `-` that the key/state/count fields are). `prefix` is the literal row kind.
[[nodiscard]] inline std::string pipe_row(std::string_view prefix,
                                          std::initializer_list<std::string_view> fields,
                                          bool& oversized) {
    std::string r(prefix);
    for (const auto f : fields) {
        r += '|';
        r += wire_field(f, oversized);
    }
    return r;
}

[[nodiscard]] inline std::string source_row(std::string_view kind, SourceState state,
                                            std::optional<std::size_t> n) {
    std::string r = "source|";
    r += kind;
    r += '|';
    r += state_token(state);
    r += '|';
    r += n ? std::to_string(*n) : std::string{"-"};
    return r;
}

/// The `homes` source row: `source|homes|<state>|<accounts or ->|<skipped or ->`. `skipped` counts the
/// listed home-root entries the account-eligibility probe positively refused (macOS: owned by a uid
/// under 500, such as /Users/Shared); `-` where no probe exists (Linux) or the roots were not listed.
[[nodiscard]] inline std::string homes_source_row(SourceState state, std::optional<std::size_t> accounts,
                                                  std::optional<std::size_t> skipped) {
    return source_row("homes", state, accounts) + '|' + (skipped ? std::to_string(*skipped) : std::string{"-"});
}

// ---------------------------------------------------------------------------
// sshd_config tokenising (misc.c strdelim_internal + argv_split)
// ---------------------------------------------------------------------------

namespace detail {

/// misc.c strdelim_internal(split_equals=1). `cur` is the cursor into the line (nullopt ==
/// the C NULL). Splits the next token on whitespace or ONE '=' and returns it; a '"' in the
/// scan is dropped and the token runs to the matching quote (no match -> nullopt, the C NULL).
inline std::optional<std::string> strdelim(std::optional<std::string>& cur) {
    if (!cur)
        return std::nullopt;
    std::string s = std::move(*cur);
    const auto p = s.find_first_of(" \t\r\n\"=");
    if (p == std::string::npos) {
        cur.reset();
        return s;
    }
    if (s[p] == '"') {
        s.erase(p, 1);
        const auto q = s.find('"', p);
        if (q == std::string::npos) {
            cur.reset();
            return std::nullopt;
        }
        std::string tok = s.substr(0, q);
        cur = s.substr(skip_wsp(s, q + 1));
        return tok;
    }
    const bool wspace = s[p] == '=';
    std::string tok = s.substr(0, p);
    std::size_t r = skip_wsp(s, p + 1);
    if (r < s.size() && s[r] == '=' && !wspace)
        r = skip_wsp(s, r + 1);
    cur = s.substr(r);
    return tok;
}

} // namespace detail

/// misc.c argv_split(s, terminate_on_comment). Quotes ' and " group, a backslash escapes
/// ' " \ and (outside quotes) a space, anything else after a backslash is literal, '#' at the
/// START of a token ends the line. nullopt == an unterminated quote.
inline std::optional<std::vector<std::string>> argv_split(std::string_view s, bool terminate_on_comment) {
    std::vector<std::string> argv;
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == ' ' || s[i] == '\t')
            continue;
        if (terminate_on_comment && s[i] == '#')
            break;
        char quote = 0;
        std::string arg;
        for (; i < s.size(); ++i) {
            if (s[i] == '\\') {
                const char nx = i + 1 < s.size() ? s[i + 1] : '\0';
                if (nx == '\'' || nx == '"' || nx == '\\' || (quote == 0 && nx == ' ')) {
                    ++i;
                    arg += s[i];
                } else {
                    arg += s[i];
                }
            } else if (quote == 0 && (s[i] == ' ' || s[i] == '\t')) {
                break;
            } else if (quote == 0 && (s[i] == '"' || s[i] == '\'')) {
                quote = s[i];
            } else if (quote != 0 && s[i] == quote) {
                quote = 0;
            } else {
                arg += s[i];
            }
        }
        argv.push_back(std::move(arg));
        if (i >= s.size()) {
            if (quote != 0)
                return std::nullopt;
            break;
        }
    }
    return argv;
}

/// One configuration line -> lowercase keyword and arguments. `invalid_quotes` is set when the
/// ARGUMENTS hold an unterminated quote (sshd rejects the line; we skip it and say so).
/// An empty/comment line, a keyword with an unmatched quote or no argument -> nullopt.
struct SshdLine {
    std::string keyword; ///< lowercased
    std::vector<std::string> args;
};

inline std::optional<SshdLine> split_sshd_line(std::string_view raw, bool& invalid_quotes) {
    // load_server_config strips leading " \t\r"; process_server_config_line strips trailing
    // whitespace and form feeds.
    std::size_t b = 0;
    while (b < raw.size() && (raw[b] == ' ' || raw[b] == '\t' || raw[b] == '\r'))
        ++b;
    std::size_t e = raw.size();
    while (e > b && (detail::is_wsp(raw[e - 1]) || raw[e - 1] == '\f'))
        --e;
    if (e == b)
        return std::nullopt;
    std::optional<std::string> cur{std::string(raw.substr(b, e - b))};
    auto kw = detail::strdelim(cur);
    if (!kw)
        return std::nullopt;
    if (kw->empty())
        kw = detail::strdelim(cur);
    if (!kw || kw->empty() || (*kw)[0] == '#')
        return std::nullopt;
    if (!cur || cur->empty())
        return std::nullopt; // "no argument after keyword"
    auto args = argv_split(*cur, true);
    if (!args) {
        invalid_quotes = true;
        return std::nullopt;
    }
    return SshdLine{detail::lower(*kw), std::move(*args)};
}

// ---------------------------------------------------------------------------
// sshd_config -> SshdConfigState
// ---------------------------------------------------------------------------

/// The first-occurrence-wins scalar keywords, in row order. `kbdinteractiveauthentication`
/// also answers to its deprecated alias `challengeresponseauthentication`, sharing the slot as
/// sshd does.
inline constexpr std::array<std::string_view, 6> kScalarKeys = {
    "permitrootlogin",       "passwordauthentication", "pubkeyauthentication",
    "kbdinteractiveauthentication", "permitemptypasswords", "usepam"};

struct ScalarSlot {
    bool set = false;
    std::string value;
    std::string origin;
};

struct CountSlot {
    std::size_t n = 0;
    std::string origin; ///< file of the first occurrence
};

/// Keywords naming a login credential source or extra login requirement this plugin does NOT
/// read. Only their PRESENCE at global scope is recorded (never a value), so such a host is not
/// reported `supported`. `inert` is the lowercase first argument that disables the keyword or is
/// its default; the first occurrence decides.
struct OtherCredentialKey {
    std::string_view keyword;
    std::string_view inert;
};
inline constexpr std::array<OtherCredentialKey, 6> kOtherCredentialKeys = {{
    {"trustedusercakeys", "none"},
    {"authorizedkeyscommand", "none"},
    {"authorizedprincipalsfile", "none"},
    {"authorizedprincipalscommand", "none"},
    {"authenticationmethods", "any"},
    {"hostbasedauthentication", "no"},
}};

struct SshdConfigState {
    std::array<ScalarSlot, kScalarKeys.size()> scalar{};
    std::vector<std::string> ports; ///< APPENDS across occurrences, like sshd
    std::string ports_origin;
    bool akf_set = false;
    std::vector<std::string> akf; ///< tokens, kept for path resolution only
    std::string akf_origin;
    std::size_t akf_count = 0;  ///< tokens written, before the kMaxAuthorizedKeysFileTokens cut
    bool akf_in_match = false;  ///< an AuthorizedKeysFile appeared inside a Match block
    unsigned cred_seen = 0;     ///< bit per kOtherCredentialKeys entry whose first occurrence was read
    bool other_credential_sources = false; ///< a kOtherCredentialKeys keyword is live at global scope
    std::array<CountSlot, 4> lists{}; ///< allowusers, allowgroups, denyusers, denygroups (args summed)
    std::size_t match_blocks = 0;
    bool invalid_quotes = false;
};

/// An Include directive, handed to the sink AT ITS POSITION. `in_match` is the containing
/// file's Match state: an Include there is not global and is not followed.
struct IncludeDirective {
    std::string pattern;
    bool in_match = false;
};
using IncludeSink = std::function<void(const IncludeDirective&)>;

/// Parses one file's text into `st`. The scalar keywords keep the FIRST value seen at global
/// scope, in directive order across files, because the caller recurses into an Include
/// INSIDE the sink (servconf.c parse_server_config_depth at the directive position). A Match
/// block is counted and from then to the end of THIS file nothing is applied (the
/// containing file's Match state never leaks out of an included file, and each file starts
/// global).
inline void parse_sshd_config(std::string_view text, std::string_view origin, SshdConfigState& st,
                              const IncludeSink& include) {
    bool in_match = false;
    std::size_t at = 0;
    while (at <= text.size()) {
        const auto nl = text.find('\n', at);
        const std::string_view line =
            nl == std::string_view::npos ? text.substr(at) : text.substr(at, nl - at);
        at = nl == std::string_view::npos ? text.size() + 1 : nl + 1;

        auto sl = split_sshd_line(line, st.invalid_quotes);
        if (!sl)
            continue;
        const std::string& kw = sl->keyword;
        auto& args = sl->args;

        if (kw == "match") {
            ++st.match_blocks;
            in_match = true;
            continue;
        }
        if (kw == "include") {
            for (const auto& a : args) {
                if (a.empty())
                    break; // sshd: "keyword Include empty argument", rest of the directive dropped
                include(IncludeDirective{a, in_match});
            }
            continue;
        }
        if (kw == "authorizedkeysfile") {
            if (in_match) {
                st.akf_in_match = true;
                continue;
            }
            if (args.empty() || st.akf_set)
                continue;
            bool bad = false;
            for (const auto& a : args)
                bad = bad || a.empty() || (args.size() > 1 && detail::lower(a) == "none");
            if (bad)
                continue; // sshd rejects an empty argument or a "none" that is not alone
            st.akf_set = true;
            st.akf_count = args.size();
            st.akf.assign(args.begin(), args.begin() + static_cast<std::ptrdiff_t>(
                                                           (std::min)(args.size(), kMaxAuthorizedKeysFileTokens)));
            st.akf_origin = std::string(origin);
            continue;
        }
        if (in_match)
            continue;

        if (const auto cred =
                std::ranges::find(kOtherCredentialKeys, kw, &OtherCredentialKey::keyword);
            cred != kOtherCredentialKeys.end()) {
            const unsigned bit =
                1u << static_cast<unsigned>(std::distance(kOtherCredentialKeys.begin(), cred));
            if ((st.cred_seen & bit) == 0 && !args.empty() && !args[0].empty()) {
                st.cred_seen |= bit;
                st.other_credential_sources =
                    st.other_credential_sources || detail::lower(args[0]) != cred->inert;
            }
            continue;
        }

        if (kw == "port") {
            if (!args.empty() && st.ports.size() < kMaxPorts) {
                if (st.ports.empty())
                    st.ports_origin = std::string(origin);
                st.ports.push_back(args[0]);
            }
            continue;
        }
        const auto list_slot = [&]() -> CountSlot* {
            if (kw == "allowusers")
                return &st.lists[0];
            if (kw == "allowgroups")
                return &st.lists[1];
            if (kw == "denyusers")
                return &st.lists[2];
            if (kw == "denygroups")
                return &st.lists[3];
            return nullptr;
        }();
        if (list_slot != nullptr) {
            std::size_t n = 0;
            for (const auto& a : args)
                n += a.empty() ? 0 : 1;
            if (n > 0 && list_slot->n == 0)
                list_slot->origin = std::string(origin);
            list_slot->n += n;
            continue;
        }
        const std::string_view key = kw == "challengeresponseauthentication"
                                         ? std::string_view{"kbdinteractiveauthentication"}
                                         : std::string_view{kw};
        for (std::size_t i = 0; i < kScalarKeys.size(); ++i) {
            if (kScalarKeys[i] != key)
                continue;
            if (!st.scalar[i].set && !args.empty() && !args[0].empty()) {
                st.scalar[i] = ScalarSlot{true, args[0], std::string(origin)};
            }
            break;
        }
    }
}

/// `include:<basename>` for a file reached through an Include, `sshd_config` for the main one.
inline std::string include_origin(std::string_view path) {
    return "include:" + std::filesystem::path(std::string(path)).filename().string();
}

// ---------------------------------------------------------------------------
// Include pattern expansion
// ---------------------------------------------------------------------------

struct IncludeSpec {
    enum class Kind { single, glob, unsupported };
    Kind kind = Kind::unsupported;
    std::string path; ///< single: the file path
    std::string dir;  ///< glob: the directory listed
    std::string leaf; ///< glob: the fnmatch pattern for the entry name
};

/// servconf.c prefixes an Include argument that does not start with '/' or '~' with SSHDIR
/// (/etc/ssh/). `~` forms need a passwd lookup and are unsupported, as is a wildcard in any
/// directory component or a backslash escape (glob(3) semantics beyond a leaf fnmatch).
inline IncludeSpec expand_include_pattern(std::string_view arg) {
    IncludeSpec out;
    if (arg.empty() || arg[0] == '~' || arg.find('\\') != std::string_view::npos)
        return out;
    std::string full = arg[0] == '/' ? std::string(arg) : "/etc/ssh/" + std::string(arg);
    const auto slash = full.rfind('/');
    std::string dir = full.substr(0, slash == 0 ? 1 : slash);
    std::string leaf = full.substr(slash + 1);
    const auto wild = [](std::string_view s) { return s.find_first_of("*?[") != std::string_view::npos; };
    if (wild(dir) || leaf.empty())
        return out;
    if (wild(leaf)) {
        out.kind = IncludeSpec::Kind::glob;
        out.dir = std::move(dir);
        out.leaf = std::move(leaf);
        return out;
    }
    out.kind = IncludeSpec::Kind::single;
    out.path = std::move(full);
    return out;
}

// ---------------------------------------------------------------------------
// Row formatters
// ---------------------------------------------------------------------------

[[nodiscard]] inline std::string config_row(std::string_view key, std::string_view value,
                                            std::string_view origin, bool& oversized) {
    return pipe_row("config", {key, value, origin}, oversized);
}

/// `default` (unset), `none`, or `custom:<n>` (n tokens). The tokens are paths and are NEVER
/// emitted (P1).
[[nodiscard]] inline std::string akf_summary(const SshdConfigState& st) {
    if (!st.akf_set)
        return "default";
    if (st.akf.size() == 1 && detail::lower(st.akf[0]) == "none")
        return "none";
    return "custom:" + std::to_string(st.akf_count);
}

/// The 13 config rows, ALWAYS all of them. `config_read == false` (sshd_config absent or
/// unreadable) -> every value `-`: the file said nothing, and defaults are not applied.
[[nodiscard]] inline std::vector<std::string> config_rows(const SshdConfigState& st, bool config_read,
                                                          bool& oversized) {
    std::vector<std::string> rows;
    const auto add = [&](std::string_view key, const std::string& value, const std::string& origin) {
        rows.push_back(config_row(key, config_read ? value : std::string{}, config_read ? origin : std::string{},
                                  oversized));
    };
    for (std::size_t i = 0; i < kScalarKeys.size(); ++i)
        add(kScalarKeys[i], st.scalar[i].value, st.scalar[i].origin);
    std::string ports;
    for (const auto& p : st.ports) {
        if (!ports.empty())
            ports += ',';
        ports += p;
    }
    add("port", ports, st.ports_origin);
    add("authorizedkeysfile", akf_summary(st), st.akf_set ? st.akf_origin : std::string{});
    static constexpr std::array<std::string_view, 4> kListKeys = {"allowusers_count", "allowgroups_count",
                                                                  "denyusers_count", "denygroups_count"};
    for (std::size_t i = 0; i < kListKeys.size(); ++i)
        add(kListKeys[i], std::to_string(st.lists[i].n), st.lists[i].origin);
    add("match_blocks", std::to_string(st.match_blocks), "");
    return rows;
}

// ---------------------------------------------------------------------------
// Service state
// ---------------------------------------------------------------------------

/// systemctl is-enabled prints exactly one of these (systemctl(1) "is-enabled"), on stdout.
inline constexpr std::array<std::string_view, 14> kSystemctlStates = {
    "enabled", "enabled-runtime", "linked", "linked-runtime", "alias",    "masked",   "masked-runtime",
    "static",  "indirect",        "disabled", "generated",    "transient", "bad",      "not-found"};

struct ServiceFact {
    std::string state; ///< a kSystemctlStates word, enabled/disabled for launchd, or `unknown`
    std::string cause; ///< failure cause (`no_output`, `unrecognised_output`); empty when the output was understood
};

/// The first line of the output, trimmed, must be exactly one state word; the exit code is not a
/// failure signal (`disabled` exits 1, `not-found` 4). `out` is stdout+stderr merged because
/// systemd 249/252 report a missing unit only on stderr: `Failed to get unit file state for
/// <unit>: No such file or directory`. That exact line with a non-zero exit is `not-found`;
/// nothing broader is (it would also take `Failed to connect to bus: No such file or directory`).
inline ServiceFact parse_systemctl_is_enabled(std::string_view out, int exit_code, std::string_view unit) {
    const auto nl = out.find('\n');
    std::string_view first = nl == std::string_view::npos ? out : out.substr(0, nl);
    while (!first.empty() && (first.front() == ' ' || first.front() == '\t' || first.front() == '\r'))
        first.remove_prefix(1);
    while (!first.empty() && (first.back() == ' ' || first.back() == '\t' || first.back() == '\r'))
        first.remove_suffix(1);
    if (first.empty())
        return {"unknown", "no_output"};
    for (const auto s : kSystemctlStates) {
        if (first == s)
            return {std::string(s), {}};
    }
    if (exit_code != 0 && !unit.empty()) {
        std::string missing = "Failed to get unit file state for ";
        missing += unit;
        missing += ": No such file or directory";
        if (first == missing)
            return {"not-found", {}};
    }
    return {"unknown", "unrecognised_output"};
}

enum class LaunchState { enabled, disabled, absent };

/// True when the output has launchd's `disabled services = {` header, i.e. it is the output
/// of the command at all.
inline bool looks_like_print_disabled(std::string_view output) {
    return output.find("disabled services") != std::string_view::npos;
}

/// `"label" => enabled|disabled` for ONE exact label (services_macos_launchd.hpp's exact-token
/// rule, reduced to a single label): the quoted label must equal `label` byte for byte and the
/// value, trimmed of space/tab/CR, must be exactly `enabled` or `disabled` ("enabledx" is
/// neither). A label with no matching line is `absent` -- NEVER `disabled`: the override
/// database only lists labels that were ever toggled.
inline LaunchState parse_print_disabled_label(std::string_view output, std::string_view label) {
    std::size_t pos = 0;
    while (pos <= output.size()) {
        const auto nl = output.find('\n', pos);
        const std::string_view line =
            nl == std::string_view::npos ? output.substr(pos) : output.substr(pos, nl - pos);
        pos = nl == std::string_view::npos ? output.size() + 1 : nl + 1;
        const auto q1 = line.find('"');
        const auto q2 = q1 == std::string_view::npos ? q1 : line.find('"', q1 + 1);
        const auto arrow = q2 == std::string_view::npos ? q2 : line.find("=>", q2);
        if (arrow == std::string_view::npos)
            continue;
        if (line.substr(q1 + 1, q2 - q1 - 1) != label)
            continue;
        std::string_view v = line.substr(arrow + 2);
        const auto b = v.find_first_not_of(" \t\r");
        if (b == std::string_view::npos)
            continue;
        v = v.substr(b);
        v = v.substr(0, v.find_last_not_of(" \t\r") + 1);
        if (v == "enabled")
            return LaunchState::enabled;
        if (v == "disabled")
            return LaunchState::disabled;
    }
    return LaunchState::absent;
}

[[nodiscard]] inline std::string service_row(std::string_view unit, std::string_view state,
                                             std::string_view mechanism) {
    bool ignored = false;
    return pipe_row("service", {unit, state, mechanism}, ignored);
}

} // namespace yuzu::remote_access_audit
