#pragma once

/**
 * platform_security_win_parsers.hpp -- the PURE layer of the Windows leg of platform_security
 * (platform_security_win.cpp): no platform header, no OS call, no I/O; unit-tested on every OS.
 * Every DECISION (absent vs denied vs failed, value -> state, which rows, the status) lives here.
 *
 * SOURCES (HKLM\SYSTEM\CurrentControlSet\Control, 64-bit view): secure_boot = SecureBoot\State
 * UEFISecureBootEnabled; code_integrity = CI\Policy (EVERY value; VerifiedAndReputablePolicyState
 * mapped), DeviceGuard (EnableVirtualizationBasedSecurity, RequirePlatformSecurityFeatures,
 * HypervisorEnforcedCodeIntegrity), DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity (Enabled)
 * and Lsa (LsaCfgFlags: 0 disabled, 1 enabled + UEFI lock, 2 enabled; Microsoft Learn "Configure
 * Credential Guard", Registry tab -- NOT under DeviceGuard; the HKLM\SOFTWARE\Policies mirror is
 * never read). CONFIGURED policy, not proof of what runs (Win32_DeviceGuard is the runtime view).
 *
 * ROW: <secure_boot|code_integrity>|windows|<key>|<raw>|<state>; state in {enabled, disabled,
 * evaluation, enabled_locked, unmodelled, absent, unreadable}. `absent` = the OS says the key/value
 * is not there (a default install has no DeviceGuard values; a BIOS/CSM boot has no SecureBoot\State):
 * a definitive row, NO token, no status effect. `unreadable` = the read failed (denied, wrong type,
 * oversized, other Win32 error, incomplete enumeration): one token (<name>:access_denied | :win32_<n> |
 * :oversized | :type_<n> | ci_policy:enumeration_incomplete), never `absent`. `unmodelled` = read but
 * not interpreted. <raw> is "-" when nothing was read. Status: the shared select_status.
 *
 * The UTF-16LE-BOM decoder and `reg export` parser drive the SAME row builders from captured
 * fixtures; a malformed or truncated export is a DecodeError, never a partial parse.
 */

#include "platform_security_parsers.hpp" // PlatformStatus + select_status: the one status decision

#include <constraint_accumulator.hpp>

#include <yuzu/string_utils.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::platform_security::win {

enum class State { enabled, disabled, evaluation, enabled_locked, unmodelled, absent, unreadable };

constexpr std::string_view state_token(State s) noexcept {
    switch (s) {
    case State::enabled: return "enabled";
    case State::disabled: return "disabled";
    case State::evaluation: return "evaluation";
    case State::enabled_locked: return "enabled_locked";
    case State::unmodelled: return "unmodelled";
    case State::absent: return "absent";
    case State::unreadable: return "unreadable";
    }
    return "unmodelled";
}

// Win32 numbers as plain integers; platform_security_win.cpp static_asserts each against the SDK.
inline constexpr std::uint32_t kErrorFileNotFound = 2;
inline constexpr std::uint32_t kErrorPathNotFound = 3;
inline constexpr std::uint32_t kErrorAccessDenied = 5;
inline constexpr std::uint32_t kErrorMoreData = 234;
inline constexpr std::uint32_t kRegSz = 1;
inline constexpr std::uint32_t kRegExpandSz = 2;
inline constexpr std::uint32_t kRegDword = 4;
inline constexpr std::uint32_t kMaxTextBytes = 4096; // a longer string value is `oversized`

// ── failure classification ──────────────────────────────────────────────

/// A failed read: `absent` (no token) iff the OS says not-found, else `unreadable` + one token.
struct Failure {
    State state{State::unreadable};
    std::string token;
    bool access_denied{false};
};

inline Failure classify_win32_failure(std::string_view name, std::uint32_t err) {
    if (err == kErrorFileNotFound || err == kErrorPathNotFound)
        return {State::absent, {}, false};
    if (err == kErrorAccessDenied)
        return {State::unreadable, std::string{name} + ":access_denied", true};
    if (err == kErrorMoreData)
        return {State::unreadable, std::string{name} + ":oversized", false};
    return {State::unreadable, std::string{name} + ":win32_" + std::to_string(err), false};
}

inline Failure unreadable_failure(std::string_view name, std::string_view cause) {
    return {State::unreadable, std::string{name} + ":" + std::string{cause}, false};
}

// ── value model + mappers ───────────────────────────────────────────────

enum class ValueKind { dword, text, other };

struct RegValue {
    ValueKind kind{ValueKind::other};
    std::uint32_t type{0};  // registry type number (other: shown in the type_<n> token)
    std::uint32_t dword{0}; // kind == dword
    std::string text;       // kind == text (UTF-8)
    std::size_t byte_len{0}; // kind == other
};

/// What the shell does with a value it found: read the 4 bytes, read the string, or
/// only note the type/size. A 32-bit value of any other size is `bad_size`.
enum class ReadPlan { dword, text, opaque, bad_size, oversized };

constexpr ReadPlan plan_value_read(std::uint32_t type, std::uint32_t size) noexcept {
    if (type == kRegDword)
        return size == 4 ? ReadPlan::dword : ReadPlan::bad_size;
    if (type == kRegSz || type == kRegExpandSz)
        return size <= kMaxTextBytes ? ReadPlan::text : ReadPlan::oversized;
    return ReadPlan::opaque;
}

enum class Map { secure_boot, sac, toggle, platform_features, lsa_cfg };

/// Every mapper: an unlisted value is `unmodelled`, never coerced.
constexpr State apply_map(Map m, std::uint32_t v) noexcept {
    switch (m) {
    case Map::secure_boot: // UEFISecureBootEnabled
    case Map::toggle:      // EnableVirtualizationBasedSecurity, HypervisorEnforcedCodeIntegrity, Enabled
        return v == 0 ? State::disabled : v == 1 ? State::enabled : State::unmodelled;
    case Map::sac: // VerifiedAndReputablePolicyState (Smart App Control): 2 = evaluation mode
        return v == 0 ? State::disabled
               : v == 1 ? State::enabled
               : v == 2 ? State::evaluation
                        : State::unmodelled;
    case Map::platform_features: // RequirePlatformSecurityFeatures: 1 Secure Boot, 3 + DMA protection
        return v == 0 ? State::disabled : (v == 1 || v == 3) ? State::enabled : State::unmodelled;
    case Map::lsa_cfg: // LsaCfgFlags: 1 = Credential Guard with UEFI lock, 2 = without
        return v == 0 ? State::disabled
               : v == 1 ? State::enabled_locked
               : v == 2 ? State::enabled
                        : State::unmodelled;
    }
    return State::unmodelled;
}

struct ExpectedValue {
    std::string_view name;    // registry value name
    std::string_view row_key; // the row's <key> column
    Map map;
};

struct KeySpec {
    std::string_view action; // secure_boot | code_integrity
    std::string_view label;  // token prefix for a key-level failure
    std::string_view path;   // under HKLM
    std::string_view prefix; // row-key prefix for values that are not in `expected`
    std::span<const ExpectedValue> expected;
    bool enumerate; // CI\Policy: read every value; else read only `expected`
    // Whether a not-found KEY OPEN is a legitimate `absent` for THIS key specifically -- not
    // every KeySpec has one. true only where a real host is known to lack the whole key (BIOS/CSM
    // boot has no SecureBoot\State; CI\Policy/DeviceGuard/its HVCI scenario subkey are genuinely
    // absent on a default, non-SAC/non-VBS install -- all confirmed by real capture). false for a
    // key that is foundational OS infrastructure present on every functioning install (Lsa) --
    // there, a not-found key-open is never a legitimate answer, so it reads `unreadable` with a
    // token instead of silently reporting "not configured" for what is actually a broken read
    // (corrupt hive, an unusually locked-down build). Per-VALUE absence inside an opened key is a
    // separate, always-legitimate case (add_key_rows's unseen-expected-value path) and is
    // unaffected by this flag.
    bool key_may_be_absent;
};

inline constexpr std::array<ExpectedValue, 1> kSecureBootValues{
    {{"UEFISecureBootEnabled", "UEFISecureBootEnabled", Map::secure_boot}}};
inline constexpr std::array<ExpectedValue, 1> kCiPolicyValues{
    {{"VerifiedAndReputablePolicyState", "ci_policy.VerifiedAndReputablePolicyState", Map::sac}}};
inline constexpr std::array<ExpectedValue, 3> kDeviceGuardValues{{
    {"EnableVirtualizationBasedSecurity", "deviceguard.EnableVirtualizationBasedSecurity", Map::toggle},
    {"RequirePlatformSecurityFeatures", "deviceguard.RequirePlatformSecurityFeatures",
     Map::platform_features},
    {"HypervisorEnforcedCodeIntegrity", "deviceguard.HypervisorEnforcedCodeIntegrity", Map::toggle},
}};
inline constexpr std::array<ExpectedValue, 1> kHvciScenarioValues{
    {{"Enabled", "deviceguard.hvci_scenario_enabled", Map::toggle}}};
inline constexpr std::array<ExpectedValue, 1> kLsaValues{
    {{"LsaCfgFlags", "lsa.LsaCfgFlags", Map::lsa_cfg}}};

inline constexpr KeySpec kSecureBootKey{"secure_boot", "secureboot_state",
                                        "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", "",
                                        kSecureBootValues, false, true};
inline constexpr KeySpec kCiPolicyKey{"code_integrity", "ci_policy",
                                      "SYSTEM\\CurrentControlSet\\Control\\CI\\Policy",
                                      "ci_policy.", kCiPolicyValues, true, true};
inline constexpr KeySpec kDeviceGuardKey{"code_integrity", "deviceguard",
                                         "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
                                         "deviceguard.", kDeviceGuardValues, false, true};
inline constexpr KeySpec kHvciScenarioKey{
    "code_integrity", "deviceguard_hvci_scenario",
    "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
    "deviceguard.hvci_scenario_", kHvciScenarioValues, false, true};
// Lsa is foundational LSA infrastructure present on every functioning NT-family install -- unlike
// its siblings above, there is no evidenced real-host case where the KEY itself is legitimately
// absent (only its LsaCfgFlags VALUE legitimately is, the default/most-common case -- see
// add_key_rows's per-value path, unaffected by this). A key-open not-found here is `unreadable`.
inline constexpr KeySpec kLsaKey{"code_integrity", "lsa", "SYSTEM\\CurrentControlSet\\Control\\Lsa",
                                 "lsa.", kLsaValues, false, false};

// ── what the shell observed, and the rows built from it ─────────────────

struct ValueOutcome {
    std::string name; // as the registry spells it
    bool ok{true};
    RegValue value;   // ok
    Failure failure;  // !ok
};

struct KeyRead {
    bool opened{true};
    Failure failure; // !opened
    std::vector<ValueOutcome> values;
    bool complete{true}; // value enumeration known complete (CI\Policy)
};

struct Row {
    std::string_view action;
    std::string key;
    std::string raw;
    State state{State::unmodelled};
};

struct Report {
    std::vector<Row> rows;
    yuzu::shared::ConstraintAccumulator acc;
    bool denied{false};
};

inline std::string format_row(const Row& r) {
    std::string out{r.action};
    out += "|windows|";
    out += yuzu::util::safe_output_field(r.key);
    out += '|';
    out += yuzu::util::safe_output_field(r.raw);
    out += '|';
    out += state_token(r.state);
    return out;
}

inline void note_failure(Report& rep, const Failure& f) {
    if (f.access_denied)
        rep.denied = true;
    if (!f.token.empty())
        rep.acc.add_failure(f.token);
}

inline bool iequals(std::string_view a, std::string_view b) {
    return a.size() == b.size() &&
           std::equal(a.begin(), a.end(), b.begin(), [](unsigned char x, unsigned char y) {
               return std::tolower(x) == std::tolower(y);
           });
}

/// The registry value's ExpectedValue entry (names are case-insensitive), or nullptr.
inline const ExpectedValue* find_expected(const KeySpec& spec, std::string_view name) {
    for (const auto& e : spec.expected)
        if (iequals(e.name, name))
            return &e;
    return nullptr;
}

/// The row's <key> column for a registry value: the table's key, else prefix + name.
inline std::string row_key(const KeySpec& spec, std::string_view name) {
    const auto* e = find_expected(spec, name);
    return e ? std::string{e->row_key} : std::string{spec.prefix} + std::string{name};
}

/// Adds the rows of one key. Key not opened: one row per expected value in the failure's state
/// (absent: no token; otherwise one key-level token). Opened: one row per value read, sorted by
/// name; an expected value that was not seen is `absent`; an expected 32-bit value of another
/// type is `unreadable` (`<row key>:type_<n>`); a value outside `expected` is `unmodelled`.
inline void add_key_rows(Report& rep, const KeySpec& spec, const KeyRead& kr) {
    if (!kr.opened) {
        // A not-found key open is `absent` only for a KeySpec that can genuinely lack the whole
        // key on a real host. For one that can't (kLsaKey), a not-found classification from
        // classify_win32_failure (which has no per-key knowledge) is overridden here to
        // `unreadable` -- the open failed for some other reason (corrupt hive, an unusually
        // locked-down build), never a clean "not configured".
        Failure f = kr.failure;
        if (f.state == State::absent && !spec.key_may_be_absent)
            f = unreadable_failure(spec.label, "key_missing");
        for (const auto& e : spec.expected)
            rep.rows.push_back({spec.action, std::string{e.row_key}, "-", f.state});
        note_failure(rep, f);
        return;
    }
    std::vector<const ValueOutcome*> vals;
    for (const auto& v : kr.values)
        vals.push_back(&v);
    std::sort(vals.begin(), vals.end(), [](const ValueOutcome* a, const ValueOutcome* b) {
        return std::lexicographical_compare(
            a->name.begin(), a->name.end(), b->name.begin(), b->name.end(),
            [](unsigned char x, unsigned char y) { return std::tolower(x) < std::tolower(y); });
    });
    std::vector<bool> seen(spec.expected.size(), false);
    for (const auto* v : vals) {
        const ExpectedValue* exp = find_expected(spec, v->name);
        if (exp)
            seen[static_cast<std::size_t>(exp - spec.expected.data())] = true;
        const std::string key = row_key(spec, v->name);
        if (!v->ok) {
            rep.rows.push_back({spec.action, key, "-", v->failure.state});
            note_failure(rep, v->failure);
            continue;
        }
        const RegValue& rv = v->value;
        if (rv.kind == ValueKind::dword) {
            rep.rows.push_back({spec.action, key, std::to_string(rv.dword),
                                exp ? apply_map(exp->map, rv.dword) : State::unmodelled});
        } else if (exp) { // a modelled 32-bit value of the wrong type
            note_failure(rep, unreadable_failure(key, "type_" + std::to_string(rv.type)));
            rep.rows.push_back({spec.action, key, "-", State::unreadable});
        } else {
            rep.rows.push_back({spec.action, key,
                                rv.kind == ValueKind::text ? rv.text
                                                           : "opaque_" + std::to_string(rv.byte_len) + "B",
                                State::unmodelled});
        }
    }
    // An incomplete enumeration only PROVES a value wasn't seen among the values it managed to
    // read; it never proves the value doesn't exist. An unseen expected value therefore reads
    // `unreadable` (with a reason token), never `absent`, when the enumeration didn't finish.
    for (std::size_t i = 0; i < spec.expected.size(); ++i)
        if (!seen[i]) {
            if (kr.complete) {
                rep.rows.push_back({spec.action, std::string{spec.expected[i].row_key}, "-", State::absent});
            } else {
                note_failure(rep, unreadable_failure(spec.expected[i].row_key, "enumeration_incomplete"));
                rep.rows.push_back({spec.action, std::string{spec.expected[i].row_key}, "-", State::unreadable});
            }
        }
    if (!kr.complete)
        rep.acc.add_failure(std::string{spec.label} + ":enumeration_incomplete");
}

inline Report build_secure_boot_report(const KeyRead& state_key) {
    Report rep;
    add_key_rows(rep, kSecureBootKey, state_key);
    return rep;
}

inline Report build_code_integrity_report(const KeyRead& ci, const KeyRead& device_guard,
                                          const KeyRead& hvci_scenario, const KeyRead& lsa) {
    Report rep;
    add_key_rows(rep, kCiPolicyKey, ci);
    add_key_rows(rep, kDeviceGuardKey, device_guard);
    add_key_rows(rep, kHvciScenarioKey, hvci_scenario);
    add_key_rows(rep, kLsaKey, lsa);
    return rep;
}

/// The ONE status decision every leg shares (platform_security_parsers.hpp): any refusal ->
/// PERMISSION_DENIED, else any token -> CONSTRAINED, else OK. `absent` rows carry no token.
inline yuzu::platform_security::PlatformStatus select_status(const Report& rep) {
    return yuzu::platform_security::select_status(rep.acc, rep.denied);
}

// ── `reg export` text: UTF-16LE decode + parser ─────────────────────────

struct DecodeError {
    std::string token; // no_bom | odd_length | bad_surrogate | no_header | truncated_line |
                       // bad_key_line | bad_dword | bad_hex | bad_value | value_before_key
};
template <class T>
using Result = std::expected<T, DecodeError>;

/// UTF-16LE (mandatory BOM FF FE) -> UTF-8. CRLF is preserved; a lone surrogate is an error.
inline Result<std::string> decode_utf16le_bom(std::span<const std::uint8_t> in) {
    if (in.size() < 2 || in[0] != 0xFF || in[1] != 0xFE)
        return std::unexpected(DecodeError{"no_bom"});
    if ((in.size() - 2) % 2 != 0)
        return std::unexpected(DecodeError{"odd_length"});
    std::string out;
    for (std::size_t i = 2; i < in.size(); i += 2) {
        std::uint32_t cp = static_cast<std::uint32_t>(in[i]) | (static_cast<std::uint32_t>(in[i + 1]) << 8);
        if (cp >= 0xDC00 && cp <= 0xDFFF)
            return std::unexpected(DecodeError{"bad_surrogate"});
        if (cp >= 0xD800 && cp <= 0xDBFF) {
            if (i + 3 >= in.size())
                return std::unexpected(DecodeError{"bad_surrogate"});
            const std::uint32_t lo = static_cast<std::uint32_t>(in[i + 2]) | (static_cast<std::uint32_t>(in[i + 3]) << 8);
            if (lo < 0xDC00 || lo > 0xDFFF)
                return std::unexpected(DecodeError{"bad_surrogate"});
            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
            i += 2;
        }
        const int n = cp < 0x80 ? 0 : cp < 0x800 ? 1 : cp < 0x10000 ? 2 : 3; // continuation bytes
        out += static_cast<char>(n == 0 ? cp : ((0xF00 >> (n + 1)) & 0xF0) | (cp >> (6 * n)));
        for (int k = n - 1; k >= 0; --k)
            out += static_cast<char>(0x80 | ((cp >> (6 * k)) & 0x3F));
    }
    return out;
}

struct RegExportKey {
    std::string path; // as exported, e.g. HKEY_LOCAL_MACHINE\SYSTEM\...
    std::vector<ValueOutcome> values;
};
using RegExport = std::vector<RegExportKey>;

namespace detail {

inline bool hex_u32(std::string_view s, std::uint32_t& out) { // whole string is hex digits
    const auto r = std::from_chars(s.data(), s.data() + s.size(), out, 16);
    return !s.empty() && r.ec == std::errc{} && r.ptr == s.data() + s.size();
}

/// `"..."` at the start of s (\\ and \" escapes), s advanced past the closing quote; false = unterminated.
inline bool parse_quoted(std::string_view& s, std::string& out) {
    out.clear();
    for (std::size_t i = 1; i < s.size(); ++i) {
        if (s[i] == '"') {
            s.remove_prefix(i + 1);
            return true;
        }
        out += (s[i] == '\\' && i + 1 < s.size()) ? s[++i] : s[i];
    }
    return false;
}

inline Result<ValueOutcome> parse_value_line(std::string_view line) {
    const auto fail = [](const char* t) { return std::unexpected(DecodeError{t}); };
    ValueOutcome v;
    if (line.starts_with("@")) {
        v.name = "@";
        line.remove_prefix(1);
    } else if (!(line.starts_with("\"") && parse_quoted(line, v.name))) {
        return fail(line.starts_with("\"") ? "truncated_line" : "bad_value");
    }
    if (!line.starts_with("=") || line.size() == 1)
        return fail("truncated_line");
    line.remove_prefix(1);
    RegValue& rv = v.value;
    if (line[0] == '"') {
        rv.kind = ValueKind::text;
        rv.type = kRegSz;
        return parse_quoted(line, rv.text) ? Result<ValueOutcome>{v} : fail("truncated_line");
    }
    if (line.starts_with("dword:")) {
        line.remove_prefix(6);
        if (line.size() < 8)
            return fail("truncated_line");
        rv = {ValueKind::dword, kRegDword, 0, {}, 0};
        return line.size() == 8 && hex_u32(line, rv.dword) ? Result<ValueOutcome>{v} : fail("bad_dword");
    }
    if (!line.starts_with("hex"))
        return fail("bad_value");
    line.remove_prefix(3); // hex: = REG_BINARY; hex(n): = registry type n
    rv.type = 3;
    if (line.starts_with("(")) {
        const auto close = line.find("):");
        if (close == std::string_view::npos)
            return fail("truncated_line");
        if (!hex_u32(line.substr(1, close - 1), rv.type))
            return fail("bad_hex");
        line.remove_prefix(close + 1);
    }
    if (!line.starts_with(":"))
        return fail("bad_value");
    line.remove_prefix(1);
    for (bool more = !line.empty(); more;) { // comma-separated two-digit bytes
        const auto comma = line.find(',');
        std::uint32_t b = 0;
        if (!(comma == 2 || (comma == std::string_view::npos && line.size() == 2)) ||
            !hex_u32(line.substr(0, 2), b))
            return fail("bad_hex");
        ++rv.byte_len;
        more = comma != std::string_view::npos;
        if (more) {
            line.remove_prefix(3);
            if (line.empty())
                return fail("truncated_line"); // trailing comma
        }
    }
    return v;
}

} // namespace detail

/// Parses `reg export` text (already UTF-8). The header line is required; hex values may continue
/// on following lines after a trailing backslash. Any malformed or truncated line fails the whole
/// parse with a token; nothing partial is returned.
inline Result<RegExport> parse_reg_export(std::string_view text) {
    const auto fail = [](const char* t) { return std::unexpected(DecodeError{t}); };
    const auto is_ws = [](char c) { return c == ' ' || c == '\t' || c == '\r'; };
    RegExport out;
    bool header = false;
    std::string pending; // a hex value being continued
    for (std::size_t pos = 0; pos < text.size();) {
        const auto nl = text.find('\n', pos);
        std::string_view raw = text.substr(pos, nl - pos); // npos: to the end
        pos = nl == std::string_view::npos ? text.size() : nl + 1;
        while (!raw.empty() && is_ws(raw.back()))
            raw.remove_suffix(1);
        while (!raw.empty() && is_ws(raw.front()))
            raw.remove_prefix(1);
        std::string logical{raw};
        if (!pending.empty()) { // continuation of a hex value
            logical = pending + logical;
            pending.clear();
        } else if (raw.empty() || raw.front() == ';') {
            continue;
        }
        if (logical.back() == '\\' && logical.find("=hex") != std::string::npos) {
            logical.pop_back();
            pending = std::move(logical);
            continue;
        }
        if (!header) {
            if (logical != "Windows Registry Editor Version 5.00")
                return fail("no_header");
            header = true;
        } else if (logical.front() == '[') {
            if (logical.back() != ']')
                return fail("truncated_line");
            if (logical.size() < 3 || logical[1] == '-')
                return fail("bad_key_line");
            out.push_back({logical.substr(1, logical.size() - 2), {}});
        } else if (out.empty()) {
            return fail("value_before_key");
        } else if (auto v = detail::parse_value_line(logical)) {
            out.back().values.push_back(std::move(*v));
        } else {
            return fail(v.error().token.c_str());
        }
    }
    if (!pending.empty())
        return fail("truncated_line"); // ended inside a continuation
    return header ? Result<RegExport>{std::move(out)} : fail("no_header");
}

/// The exported key whose path is HKEY_LOCAL_MACHINE\<path> (case-insensitive), or nullptr.
inline const RegExportKey* find_key(const RegExport& e, std::string_view path) {
    const std::string want = "HKEY_LOCAL_MACHINE\\" + std::string{path};
    for (const auto& k : e)
        if (iequals(k.path, want))
            return &k;
    return nullptr;
}

/// A KeyRead from an exported key (what the TU would have observed reading it live).
/// The KeyRead the shell would have produced for an exported key. The shell reads every value of an
/// `enumerate` key but ONLY the named ones of any other (one query per name, a missing one is an
/// `absent` outcome), so `spec` reproduces that: a real export holds values the plugin never asks
/// for (PolicyPublisher, CachedDrtmAuthIndex) and lacks ones it does.
inline KeyRead key_read_from_export(const RegExportKey* k, const KeySpec* spec = nullptr) {
    KeyRead kr;
    if (!k)
        return {false, classify_win32_failure("export", kErrorFileNotFound), {}, true};
    for (const auto& v : k->values)
        if (!spec || spec->enumerate || find_expected(*spec, v.name))
            kr.values.push_back(v);
    if (spec && !spec->enumerate)
        for (const auto& e : spec->expected) {
            const bool present = std::any_of(kr.values.begin(), kr.values.end(), [&](const ValueOutcome& v) {
                return find_expected(*spec, v.name) == &e;
            });
            if (!present) {
                ValueOutcome o;
                o.name = std::string{e.name};
                o.ok = false;
                o.failure = classify_win32_failure("export", kErrorFileNotFound);
                kr.values.push_back(std::move(o));
            }
        }
    return kr;
}

} // namespace yuzu::platform_security::win
