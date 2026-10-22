#pragma once

/**
 * registry_parsers.hpp -- the registry plugin's PURE layer (no windows.h, no I/O, no clock; unit-tested
 * on every host; the shell is registry_win.cpp, the logic over an injected registry registry_core.hpp):
 * value encoders, the key-path / value-name validators (the trust boundary of every mutating action),
 * the error tokens, and the audit-line renderer.
 *
 * Limits come from Microsoft's "Registry Element Size Limits" (key name 255 characters, value name
 * 16,383); RegSetValueExW's cbData must include the terminating NUL of a REG_SZ / REG_EXPAND_SZ /
 * REG_MULTI_SZ, which is why every string encoder appends it.
 */

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <yuzu/log_token.hpp>

#include "user_profile_model.hpp"
#include "wire_utf8.hpp"

namespace yuzu::registry {

// ── limits ───────────────────────────────────────────────────────────────

inline constexpr std::size_t kMaxKeyPathBytes = 255;
inline constexpr std::size_t kMaxKeyComponents = 32;
inline constexpr std::size_t kMaxValueNameBytes = 16383;
/// Largest value this plugin will write or read back for verification.
inline constexpr std::size_t kMaxWriteBytes = 1024 * 1024;
/// A previous value is captured up to this many bytes; `OldValue::total` keeps the full size.
inline constexpr std::size_t kCaptureValueCap = 4096;
/// delete_key: nodes (the key itself plus its values) counted by the bounded enumeration before `capped`;
/// past it `counted_values` is a lower bound.
inline constexpr std::size_t kMaxTreeNodes = 10000;
/// Audit line budgets: raw bytes of old/new data and characters of a name token.
inline constexpr std::size_t kAuditHexCapBytes = 256;
inline constexpr std::size_t kAuditTokenCap = 256;

// ── token vocabulary ─────────────────────────────────────────────────────

inline constexpr std::string_view kTokAccessDenied = "access_denied";
inline constexpr std::string_view kTokKeyNotFound = "key_not_found";
inline constexpr std::string_view kTokRootLevelCreate = "root_level_create";
inline constexpr std::string_view kTokValueNotFound = "value_not_found";
inline constexpr std::string_view kTokKeyIsLink = "key_is_link";
inline constexpr std::string_view kTokConcurrentChange = "concurrent_change";
inline constexpr std::string_view kTokInvalidType = "invalid_type";
inline constexpr std::string_view kTokValueOverflow = "value_overflow";
inline constexpr std::string_view kTokInvalidData = "invalid_data";
inline constexpr std::string_view kTokInvalidKeyPath = "invalid_key_path";
inline constexpr std::string_view kTokInvalidValueName = "invalid_value_name";
inline constexpr std::string_view kTokVerifyMismatch = "verify_mismatch";
inline constexpr std::string_view kTokKeyHasSubkeys = "key_has_subkeys";

// Win32 codes this layer branches on (registry_win.cpp static_asserts each against the SDK).
inline constexpr long kErrorSuccess = 0;
inline constexpr long kErrorFileNotFound = 2;
inline constexpr long kErrorPathNotFound = 3;
inline constexpr long kErrorAccessDenied = 5;
inline constexpr long kErrorNotSupported = 50;
inline constexpr long kErrorMoreData = 234;
inline constexpr long kErrorNoMoreItems = 259;
inline constexpr long kErrorKeyDeleted = 1018;

// ── hives ────────────────────────────────────────────────────────────────

enum class Hive { hklm, hkcu, hkcr, hku };

[[nodiscard]] inline std::optional<Hive> parse_hive(std::string_view s) noexcept {
    if (s == "HKLM") return Hive::hklm;
    if (s == "HKCU") return Hive::hkcu;
    if (s == "HKCR") return Hive::hkcr;
    if (s == "HKU") return Hive::hku;
    return std::nullopt;
}

/// Whether the fast open (registry_core.hpp open_fast) may be tried for `h`: HKLM and HKU have one fixed kernel
/// name. HKCU resolves per calling user (impersonation) and HKCR is a merged view of two trees, so both always
/// take the component walk.
[[nodiscard]] constexpr bool fast_open_hive(Hive h) noexcept { return h == Hive::hklm || h == Hive::hku; }

[[nodiscard]] constexpr std::string_view hive_name(Hive h) noexcept {
    switch (h) {
    case Hive::hklm: return "HKLM";
    case Hive::hkcu: return "HKCU";
    case Hive::hkcr: return "HKCR";
    case Hive::hku: return "HKU";
    }
    return "HKLM";
}

// ── value types and encoders ─────────────────────────────────────────────

/// The six writable types, by name (case-sensitive). REG_NONE / REG_LINK / garbage are not writable.
[[nodiscard]] inline std::optional<std::uint32_t> parse_reg_type(std::string_view s) noexcept {
    using namespace yuzu::profiles;
    for (const std::uint32_t t : {kRegSz, kRegExpandSz, kRegBinary, kRegDword, kRegMultiSz, kRegQword})
        if (s == reg_type_name(t)) return t;
    return std::nullopt;
}

[[nodiscard]] constexpr bool is_writable_type(std::uint32_t t) noexcept {
    using namespace yuzu::profiles;
    return t == kRegSz || t == kRegExpandSz || t == kRegBinary || t == kRegDword ||
           t == kRegMultiSz || t == kRegQword;
}

struct Encoded {
    std::vector<std::uint8_t> bytes;
    std::string_view error; ///< empty = ok, else a kTok* token
};

[[nodiscard]] inline int hex_digit(char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/// Decodes an even-length hex string (either case). False on odd length or a non-hex character. A bool +
/// out-parameter rather than std::expected (cpp-conventions.md:127) on purpose: "not hex" is the only
/// failure, each caller maps it to its own token, and the caller owns the destination buffer.
[[nodiscard]] inline bool hex_decode(std::string_view hex, std::vector<std::uint8_t>& out) {
    out.clear();
    if (hex.size() % 2 != 0) return false;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        const int hi = hex_digit(hex[i]);
        const int lo = hex_digit(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<std::uint8_t>(hi * 16 + lo));
    }
    return true;
}

namespace detail {

inline void put_le(std::vector<std::uint8_t>& out, std::uint64_t v, int bytes) {
    for (int i = 0; i < bytes; ++i) out.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF));
}

/// True when the last `n` UTF-16 code units of `b` are all NUL.
[[nodiscard]] inline bool ends_with_nuls(std::span<const std::uint8_t> b, std::size_t n) {
    if (b.size() < n * 2) return false;
    for (std::size_t i = b.size() - n * 2; i < b.size(); ++i)
        if (b[i] != 0) return false;
    return true;
}

/// ASCII-only lower-casing (registry key and value names compare case-insensitively).
[[nodiscard]] inline std::string fold_ascii(std::string_view s) {
    std::string o{s};
    for (char& c : o)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
    return o;
}

} // namespace detail

/// Strict UTF-8 -> UTF-16LE bytes (no terminator). False on malformed UTF-8 or an embedded NUL
/// (wire_utf8's utf8_scalar_len rejects NUL, overlongs, surrogates and truncated sequences). A bool +
/// out-parameter rather than std::expected (cpp-conventions.md:127) on purpose: `out` is an ACCUMULATOR
/// (the REG_MULTI_SZ encoder appends one record per call), so a returned buffer would force a
/// concatenation copy per record, and malformed UTF-8 is the only failure.
[[nodiscard]] inline bool utf8_to_utf16le(std::string_view s, std::vector<std::uint8_t>& out) {
    const auto put = [&](std::uint32_t u) { detail::put_le(out, u, 2); };
    for (std::size_t i = 0; i < s.size();) {
        const std::size_t n = yuzu::shared::utf8_scalar_len(s, i);
        if (n == 0) return false;
        const auto b = [&](std::size_t k) { return static_cast<std::uint32_t>(static_cast<unsigned char>(s[i + k])); };
        std::uint32_t cp = 0;
        switch (n) {
        case 1: cp = b(0); break;
        case 2: cp = ((b(0) & 0x1F) << 6) | (b(1) & 0x3F); break;
        case 3: cp = ((b(0) & 0x0F) << 12) | ((b(1) & 0x3F) << 6) | (b(2) & 0x3F); break;
        default:
            cp = ((b(0) & 0x07) << 18) | ((b(1) & 0x3F) << 12) | ((b(2) & 0x3F) << 6) | (b(3) & 0x3F);
            break;
        }
        if (cp >= 0x10000) {
            cp -= 0x10000;
            put(0xD800 + (cp >> 10));
            put(0xDC00 + (cp & 0x3FF));
        } else {
            put(cp);
        }
        i += n;
    }
    return true;
}

/// Shape rules for bytes that arrive as data_hex (and for restoring a captured previous value):
/// DWORD exactly 4 bytes, QWORD exactly 8, SZ / EXPAND_SZ an even count ending in a NUL code unit,
/// MULTI_SZ an even count (>= 4) ending in a double NUL, BINARY anything. Everything is capped at
/// kMaxWriteBytes.
[[nodiscard]] inline std::string_view check_value_shape(std::uint32_t type,
                                                        std::span<const std::uint8_t> b) {
    using namespace yuzu::profiles;
    if (b.size() > kMaxWriteBytes) return kTokValueOverflow;
    switch (type) {
    case kRegDword: return b.size() == 4 ? std::string_view{} : kTokInvalidData;
    case kRegQword: return b.size() == 8 ? std::string_view{} : kTokInvalidData;
    case kRegSz:
    case kRegExpandSz:
        return (b.size() >= 2 && b.size() % 2 == 0 && detail::ends_with_nuls(b, 1)) ? std::string_view{}
                                                                                    : kTokInvalidData;
    case kRegMultiSz:
        return (b.size() >= 4 && b.size() % 2 == 0 && detail::ends_with_nuls(b, 2)) ? std::string_view{}
                                                                                    : kTokInvalidData;
    case kRegBinary: return {};
    default: return kTokInvalidType;
    }
}

/// Encodes a value for RegSetValueExW. `data_hex_present` says the caller provided data_hex: then
/// `value` must be empty (else invalid_data) and the hex is shape-checked per type (an EMPTY present
/// data_hex is the zero-byte form, valid only for REG_BINARY). Otherwise `value` is the text form:
/// decimal digits for DWORD / QWORD (overflow -> value_overflow), UTF-8 for SZ / EXPAND_SZ,
/// LF-separated non-empty records for MULTI_SZ (empty text = the lone double NUL), hex for BINARY.
/// Everything is capped at kMaxWriteBytes.
[[nodiscard]] inline Encoded encode_value(std::uint32_t type, std::string_view value,
                                          std::string_view data_hex, bool data_hex_present) {
    using namespace yuzu::profiles;
    Encoded r;
    if (!is_writable_type(type)) {
        r.error = kTokInvalidType;
        return r;
    }
    if (data_hex_present) {
        if (!value.empty()) {
            r.error = kTokInvalidData;
            return r;
        }
        if (data_hex.size() > kMaxWriteBytes * 2) {
            r.error = kTokValueOverflow;
            return r;
        }
        if (!hex_decode(data_hex, r.bytes)) {
            r.bytes.clear();
            r.error = kTokInvalidData;
            return r;
        }
        r.error = check_value_shape(type, r.bytes);
        if (!r.error.empty()) r.bytes.clear();
        return r;
    }
    switch (type) {
    case kRegDword:
    case kRegQword: {
        const bool wide = type == kRegQword;
        std::uint64_t v = 0;
        const char* end = value.data() + value.size();
        const auto [p, ec] = std::from_chars(value.data(), end, v);
        if (value.empty() || ec == std::errc::invalid_argument || (ec == std::errc{} && p != end)) {
            r.error = kTokInvalidData;
        } else if (ec == std::errc::result_out_of_range || (!wide && v > 0xFFFFFFFFull)) {
            r.error = kTokValueOverflow;
        } else {
            detail::put_le(r.bytes, v, wide ? 8 : 4);
        }
        return r;
    }
    case kRegSz:
    case kRegExpandSz:
        if (value.size() > kMaxWriteBytes) {
            r.error = kTokValueOverflow;
        } else if (!utf8_to_utf16le(value, r.bytes)) {
            r.bytes.clear();
            r.error = kTokInvalidData;
        } else {
            detail::put_le(r.bytes, 0, 2);
            if (r.bytes.size() > kMaxWriteBytes) {
                r.bytes.clear();
                r.error = kTokValueOverflow;
            }
        }
        return r;
    case kRegMultiSz: {
        if (value.size() > kMaxWriteBytes) {
            r.error = kTokValueOverflow;
            return r;
        }
        if (!value.empty()) {
            for (std::size_t pos = 0; pos <= value.size();) {
                const std::size_t nl = std::min(value.find('\n', pos), value.size());
                const std::string_view rec = value.substr(pos, nl - pos);
                if (rec.empty() || !utf8_to_utf16le(rec, r.bytes)) {
                    r.bytes.clear();
                    r.error = kTokInvalidData;
                    return r;
                }
                detail::put_le(r.bytes, 0, 2);
                pos = nl + 1;
            }
        }
        detail::put_le(r.bytes, 0, 2); // the list terminator (the lone double NUL when empty)
        if (value.empty()) detail::put_le(r.bytes, 0, 2);
        if (r.bytes.size() > kMaxWriteBytes) {
            r.bytes.clear();
            r.error = kTokValueOverflow;
        }
        return r;
    }
    default: // REG_BINARY: `value` is hex
        if (value.size() > kMaxWriteBytes * 2) {
            r.error = kTokValueOverflow;
        } else if (!hex_decode(value, r.bytes)) {
            r.bytes.clear();
            r.error = kTokInvalidData;
        }
        return r;
    }
}

/// Hex of the first min(bytes.size(), cap) bytes, then `~<total>` when `total` exceeds what is
/// shown (bytes dropped by the caller's own capture cap count too).
[[nodiscard]] inline std::string render_hex(std::span<const std::uint8_t> bytes, std::size_t cap,
                                            std::size_t total) {
    const std::size_t shown = std::min(bytes.size(), cap);
    std::string out = yuzu::profiles::hex_encode(bytes.first(shown));
    if (total > shown) out += "~" + std::to_string(total);
    return out;
}

// ── validators ───────────────────────────────────────────────────────────

[[nodiscard]] inline bool has_control_byte(std::string_view s) noexcept {
    return std::any_of(s.begin(), s.end(), [](char c) {
        const auto u = static_cast<unsigned char>(c);
        return u < 0x20 || u == 0x7F;
    });
}

[[nodiscard]] inline std::vector<std::string_view> split_key(std::string_view key) {
    std::vector<std::string_view> parts;
    std::size_t pos = 0;
    while (pos <= key.size()) {
        const std::size_t bs = std::min(key.find('\\', pos), key.size());
        parts.push_back(key.substr(pos, bs - pos));
        pos = bs + 1;
    }
    return parts;
}

/// "" when `key` is an acceptable path relative to a hive root, else a kTok* token. Rejects: empty,
/// > 255 bytes, > 32 components, an empty / `.` / `..` component (so a leading, trailing or doubled
/// backslash), a hive alias as the FIRST component (the hive is its own parameter), NUL / control
/// bytes and invalid UTF-8. A forward slash is ordinary key-name text (e.g. `application/pdf`).
[[nodiscard]] inline std::string_view validate_key_path(std::string_view key) {
    if (key.empty() || key.size() > kMaxKeyPathBytes || has_control_byte(key) ||
        yuzu::shared::count_invalid_wire_bytes(key) != 0)
        return kTokInvalidKeyPath;
    const auto parts = split_key(key);
    if (parts.size() > kMaxKeyComponents) return kTokInvalidKeyPath;
    for (const auto p : parts)
        if (p.empty() || p == "." || p == "..") return kTokInvalidKeyPath;
    constexpr std::array<std::string_view, 10> kAliases{
        "hklm", "hkcu", "hkcr", "hku", "hkcc", "hkey_local_machine", "hkey_current_user",
        "hkey_classes_root", "hkey_users", "hkey_current_config"};
    const std::string head = detail::fold_ascii(parts.front());
    for (const auto a : kAliases)
        if (head == a) return kTokInvalidKeyPath;
    return {};
}

/// "" or kTokInvalidValueName. The empty name is the key's default value and is allowed.
[[nodiscard]] inline std::string_view validate_value_name(std::string_view name) {
    if (name.size() > kMaxValueNameBytes || has_control_byte(name) ||
        yuzu::shared::count_invalid_wire_bytes(name) != 0)
        return kTokInvalidValueName;
    return {};
}

// ── Win32 return codes -> tokens ─────────────────────────────────────────

enum class Missing { key, value };

/// "" for success; access_denied; key_not_found / value_not_found for FILE / PATH not found
/// (`what` says which object the call addressed); concurrent_change for ERROR_KEY_DELETED; else
/// `win32:<code>`.
[[nodiscard]] inline std::string rc_token(long rc, Missing what) {
    switch (rc) {
    case kErrorSuccess: return {};
    case kErrorAccessDenied: return std::string{kTokAccessDenied};
    case kErrorFileNotFound:
    case kErrorPathNotFound:
        return std::string{what == Missing::key ? kTokKeyNotFound : kTokValueNotFound};
    case kErrorKeyDeleted: return std::string{kTokConcurrentChange};
    default: return "win32:" + std::to_string(rc);
    }
}

// ── previous-value capture ───────────────────────────────────────────────

enum class OldState { absent, present, unreadable };

inline constexpr std::array<std::string_view, 3> kOldStateNames{"absent", "present", "unreadable"};
static_assert(kOldStateNames[static_cast<std::size_t>(OldState::unreadable)] == "unreadable"); // indexed by enum value
[[nodiscard]] constexpr std::string_view old_state_name(OldState s) noexcept {
    return kOldStateNames[static_cast<std::size_t>(s)];
}

/// The state of one value BEFORE a mutation: `bytes` holds up to kCaptureValueCap of it, `total` the
/// full size. `error` is the token when unreadable.
struct OldValue {
    OldState state = OldState::absent;
    std::uint32_t type = 0;
    std::vector<std::uint8_t> bytes;
    std::size_t total = 0;
    std::string error;
};

// ── audit line ───────────────────────────────────────────────────────────

/// Neutralises untrusted text for an `audit|k=v|...` line: invalid UTF-8 -> '?', control bytes,
/// space, '=' and ',' (yuzu::log_token) -> '_', and '|' -> '_' (log_token does not map the field
/// separator). Over `cap` bytes it is cut on a character boundary and gets `~<total length>`.
[[nodiscard]] inline std::string audit_token(std::string_view s, std::size_t cap = kAuditTokenCap) {
    std::string scrubbed{s};
    yuzu::shared::scrub_wire_bytes(scrubbed);
    std::string t = yuzu::log_token(scrubbed);
    std::replace(t.begin(), t.end(), '|', '_');
    if (t.size() <= cap) return t.empty() ? std::string{"-"} : t;
    std::size_t cut = cap;
    while (cut > 0 && (static_cast<unsigned char>(t[cut]) & 0xC0) == 0x80) --cut;
    return t.substr(0, cut) + "~" + std::to_string(t.size());
}

struct AuditRecord {
    std::string op, hive, key, name, type_name;
    long long len = -1;                 ///< new data length in bytes; -1 = "-"
    std::string result = "ok";          ///< ok | refused | failed
    std::string reason;                 ///< a token; "" = "-"
    std::string verify;                 ///< ok | mismatch; "" = "-"
    int dry_run = -1;                   ///< 0 / 1; -1 = "-"
    long long counted_keys = -1, counted_values = -1;
    int capped = -1;
    std::string sid;
    std::string old_state;              ///< absent | present | unreadable; "" = "-"
    std::string old_type;
    std::vector<std::uint8_t> old_bytes;
    std::size_t old_total = 0;
    bool has_old = false;
    std::vector<std::uint8_t> new_bytes;
    std::size_t new_total = 0;
    bool has_new = false;
};

namespace detail {

/// A numeric column: the value, or "-" for the unset (negative) sentinel.
[[nodiscard]] inline std::string num(long long v) { return v < 0 ? std::string{"-"} : std::to_string(v); }

/// A text column: the string, or "-" when empty.
[[nodiscard]] inline std::string dash(const std::string& s) { return s.empty() ? std::string{"-"} : s; }

} // namespace detail

/// One `audit|op=...` line. Grammar and producer contract: README "Audit line grammar and producer contract".
/// Order: `result=`, `reason=` and `verify=` come BEFORE the caller-sized `key=` and `name=`, so a line cut at
/// the server's byte bound loses only the tail and the server still reads the result. Every field is a token
/// without '|', space, '=' or ',' except where noted; no byte of LF, CR or '|' survives in any field; the
/// whole line stays < 2 KiB by construction (key and name cap at 256 bytes + marker, old / new at 256 raw
/// bytes each).
[[nodiscard]] inline std::string render_audit_line(const AuditRecord& r) {
    using detail::dash;
    using detail::num;
    std::string o = "audit|op=" + audit_token(r.op, 64);
    o += "|hive=" + audit_token(r.hive, 64);
    o += "|result=" + dash(r.result);
    o += "|reason=" + audit_token(r.reason, 64);
    o += "|verify=" + dash(r.verify);
    o += "|key=" + audit_token(r.key);
    o += "|name=" + audit_token(r.name);
    o += "|type=" + audit_token(r.type_name, 32);
    o += "|len=" + num(r.len);
    o += "|dry_run=" + num(r.dry_run);
    o += "|counted_keys=" + num(r.counted_keys);
    o += "|counted_values=" + num(r.counted_values);
    o += "|capped=" + num(r.capped);
    o += "|sid=" + audit_token(r.sid, 64);
    o += "|old_state=" + dash(r.old_state);
    o += "|old_type=" + dash(r.old_type);
    o += "|old=" + (r.has_old ? render_hex(r.old_bytes, kAuditHexCapBytes, r.old_total) : "-");
    o += "|new=" + (r.has_new ? render_hex(r.new_bytes, kAuditHexCapBytes, r.new_total) : "-");
    return o;
}

} // namespace yuzu::registry
