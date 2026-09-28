#pragma once

/**
 * system_hardening_win_parsers.hpp -- pure decoders for the Windows leg of the
 * system_hardening plugin (system_hardening_win.cpp). No <windows.h>, no OS
 * call, no I/O; unit-tested on every OS (test_system_hardening_win_parsers.cpp).
 *
 * 1. HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel values
 *    `MitigationOptions` / `MitigationAuditOptions` (REG_BINARY, documented
 *    16/24 bytes = 2/3 little-endian QWORDs; an 8-byte REG_QWORD, which
 *    Microsoft's documented steps for untrusted-font blocking write, decodes
 *    as the same single QWORD -- decode_registry_value). The FIRST QWORD is the kernel's
 *    system-wide mitigation option map: one nibble per policy (nibble n holds
 *    bits [4n, 4n+3]), in the order of the kernel's PS_MITIGATION_OPTION
 *    enumeration. That order is undocumented by Microsoft. It is NOT the
 *    <winbase.h> PROCESS_CREATION_MITIGATION_POLICY_* flag layout (the-rig
 *    capture refuted that for nibbles 0 and 1). EVERY nibble is a
 *    two-bit value: 0 default, 1 on, 2 off, 3..15 = per-policy meaning
 *    (reserved/opt-out/audit) -> `unmodelled`. Nibble index -> policy:
 *      0 dep, 1 sehop, 2 force_relocate_images, 3 heap_terminate,
 *      4 aslr_bottom_up, 5 aslr_high_entropy, 6 strict_handle_checks,
 *      7 win32k_system_call_disable, 8 extension_point_disable,
 *      9 prohibit_dynamic_code, 10 cfg, 11 block_non_microsoft_binaries,
 *      12 font_disable, 13 image_load_no_remote, 14 image_load_no_low_label,
 *      15 image_load_prefer_system32.
 *    There is no separate DEP-ATL-thunk bit in this value. Later QWORDs are
 *    beyond the documented table: one row, `unmodelled` when non-zero.
 *    EVIDENCE: CONFIRMED on hardware by the capture from the-rig recorded in
 *    fixtures/wave8/system_hardening/windows/mitigation_options.hex and its
 *    .provenance.txt -- `Set-ProcessMitigation -System -Enable DEP,SEHOP,
 *    BottomUp,HighEntropy,CFG` set exactly nibbles 0, 1, 4, 5 and 10, each to
 *    1, and Get-ProcessMitigation -System reports those five ON -- but ONLY
 *    for indices 0 (dep), 1 (sehop), 4 (aslr_bottom_up), 5
 *    (aslr_high_entropy) and 10 (cfg). Indices 2, 3, 6-9 and 11-15 are
 *    inferred by position, unverified on hardware. The fixture test fails
 *    loudly (never skips) if the capture is missing.
 * 2. The agent's own GetProcessMitigationPolicy `Flags` DWORD
 *    (decode_self_policy): effective policy, on/off only.
 * 3. A failed Win32 read (classify_win32_failure): the OS definitively saying
 *    the value / policy is not there is `absent` and carries NO failure token;
 *    every other failure is `unreadable` with exactly one token. The one
 *    exception is the Session Manager\kernel KEY itself (ReadSource::structural_key):
 *    it exists on every install, so a not-found open is `unreadable` +
 *    `<name>:key_missing`, never a clean `absent`.
 *
 * ROW: posture|windows|<policy>|<raw>|<state>, state in {on, off, default,
 * unmodelled, absent, unreadable}. `absent` = the OS says it does not exist;
 * `unreadable` = the read failed. Never one state for both, and only
 * `unreadable` adds a reason token (absence never lowers the result status).
 * <raw> is "-" when nothing was read (absent/unreadable), matching
 * system_hardening_parsers.hpp. A value that was not decoded reports ONE row
 * under its registry row name (`mitigation_options` / `mitigation_audit_options`),
 * and a failed self policy ONE row under `self.dep` / `self.aslr` / `self.cfg`.
 * Never throws (bad_alloc aside); fallible functions return std::expected.
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::system_hardening::mitigation {

enum class PolicyState { on, off, default_state, unmodelled };

constexpr std::string_view state_token(PolicyState s) {
    switch (s) {
    case PolicyState::on:
        return "on";
    case PolicyState::off:
        return "off";
    case PolicyState::default_state:
        return "default";
    case PolicyState::unmodelled:
        return "unmodelled";
    }
    return "unmodelled";
}

struct MitigationRow {
    std::string policy; // e.g. "mitigation.dep"
    std::string raw;    // registry rows: "0x<hex>" nibble value; self rows: Flags in decimal
    PolicyState state{PolicyState::unmodelled};
};

struct DecodeError {
    std::string token; // registry decode: empty_blob | odd_length | not_qword_aligned | oversized |
                       // type_<n>; parse_hex_blob only (test fixtures, never the agent):
                       // no_hex_digits | odd_hex_digits | bad_hex
};

template <class T>
using Result = std::expected<T, DecodeError>;

/// Documented value is 16/24 bytes; anything past this is not that value.
inline constexpr std::size_t kMaxBlobBytes = 256;

/// All fields are machine tokens (never OS free text): no escaping needed.
inline std::string format_posture_row(std::string_view policy, std::string_view raw,
                                      std::string_view state) {
    std::string out = "posture|windows|";
    out += policy;
    out += '|';
    out += raw;
    out += '|';
    out += state;
    return out;
}

inline std::string format_posture_row(const MitigationRow& r) {
    return format_posture_row(r.policy, r.raw, state_token(r.state));
}

namespace detail {

struct PolicyDef {
    std::string_view name;
    std::uint8_t nibble; // nibble index within the first QWORD (0..15); every nibble is two-bit
};

// Kernel option map, one nibble per policy in PS_MITIGATION_OPTION order (see the
// header comment: indices 0, 1, 4, 5, 10 confirmed by the rig capture, the rest
// inferred by position).
inline constexpr std::array<PolicyDef, 16> kPolicyTable{{
    {"dep", 0},                           // NX                          (rig-confirmed)
    {"sehop", 1},                         // SEHOP                       (rig-confirmed)
    {"force_relocate_images", 2},         // ForceRelocateImages
    {"heap_terminate", 3},                // HeapTerminate
    {"aslr_bottom_up", 4},                // BottomUpASLR                (rig-confirmed)
    {"aslr_high_entropy", 5},             // HighEntropyASLR             (rig-confirmed)
    {"strict_handle_checks", 6},          // StrictHandleChecks
    {"win32k_system_call_disable", 7},    // Win32kSystemCallDisable
    {"extension_point_disable", 8},       // ExtensionPointDisable
    {"prohibit_dynamic_code", 9},         // ProhibitDynamicCode
    {"cfg", 10},                          // ControlFlowGuard            (rig-confirmed)
    {"block_non_microsoft_binaries", 11}, // BlockNonMicrosoftBinaries
    {"font_disable", 12},                 // FontDisable
    {"image_load_no_remote", 13},         // ImageLoadNoRemote
    {"image_load_no_low_label", 14},      // ImageLoadNoLowLabel
    {"image_load_prefer_system32", 15},   // ImageLoadPreferSystem32
}};

inline std::string hex_of(std::uint64_t v, int min_digits = 1) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string digits;
    do {
        digits.insert(digits.begin(), kHex[v & 0xF]);
        v >>= 4;
    } while (v != 0);
    while (static_cast<int>(digits.size()) < min_digits)
        digits.insert(digits.begin(), '0');
    return "0x" + digits;
}

inline std::uint64_t le_qword(std::span<const std::uint8_t> in, std::size_t qword_index) {
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < 8; ++i)
        v |= static_cast<std::uint64_t>(in[qword_index * 8 + i]) << (8 * i);
    return v;
}

} // namespace detail

/// Decodes one MitigationOptions/MitigationAuditOptions blob; `prefix` starts
/// every policy name. A 0-byte, oversized, odd-length or non-QWORD-multiple blob is a
/// DecodeError, never a partial decode.
inline Result<std::vector<MitigationRow>>
decode_mitigation_options(std::span<const std::uint8_t> blob, std::string_view prefix) {
    if (blob.empty())
        return std::unexpected(DecodeError{"empty_blob"});
    if (blob.size() > kMaxBlobBytes)
        return std::unexpected(DecodeError{"oversized"});
    if (blob.size() % 2 != 0)
        return std::unexpected(DecodeError{"odd_length"});
    if (blob.size() % 8 != 0)
        return std::unexpected(DecodeError{"not_qword_aligned"});

    const std::uint64_t q0 = detail::le_qword(blob, 0);
    std::vector<MitigationRow> rows;

    for (const auto& def : detail::kPolicyTable) {
        const auto nib = static_cast<std::uint8_t>((q0 >> (4 * def.nibble)) & 0xF);
        MitigationRow row;
        row.policy = std::string{prefix} + std::string{def.name};
        row.raw = detail::hex_of(nib);
        switch (nib) {
        case 0:
            row.state = PolicyState::default_state;
            break;
        case 1:
            row.state = PolicyState::on;
            break;
        case 2:
            row.state = PolicyState::off;
            break;
        default: // 3..15: per-policy meaning (reserved / opt-out / audit) -- not modelled
            row.state = PolicyState::unmodelled;
            break;
        }
        rows.push_back(std::move(row));
    }

    // QWORDs beyond the table.
    for (std::size_t q = 1; q < blob.size() / 8; ++q) {
        const std::uint64_t v = detail::le_qword(blob, q);
        rows.push_back({std::string{prefix} + "ext_q" + std::to_string(q),
                        detail::hex_of(v, 16),
                        v == 0 ? PolicyState::default_state : PolicyState::unmodelled});
    }
    return rows;
}

/// Registry value types the leg distinguishes, as plain numbers (winnt.h REG_BINARY / REG_QWORD;
/// system_hardening_win.cpp static_asserts each against the SDK).
inline constexpr std::uint32_t kRegBinary = 3;
inline constexpr std::uint32_t kRegQword = 11;

/// Decodes one Session Manager\kernel value as RegQueryValueExW returned it. REG_BINARY is the
/// form the documentation describes and decode_mitigation_options takes it whole. REG_QWORD is
/// what Microsoft's documented registry steps for untrusted-font blocking write (for example
/// 0x1000000000000, nibble 12); an 8-byte REG_QWORD is stored little-endian, byte-identical to an
/// 8-byte REG_BINARY, so it decodes the same way. Any other type, and a REG_QWORD that is not 8
/// bytes (not a QWORD at all), is DecodeError `type_<n>` -- never a guessed decode.
inline Result<std::vector<MitigationRow>> decode_registry_value(std::uint32_t type,
                                                                std::span<const std::uint8_t> data,
                                                                std::string_view prefix) {
    const bool binary = type == kRegBinary;
    const bool qword = type == kRegQword && data.size() == 8;
    if (!binary && !qword)
        return std::unexpected(DecodeError{"type_" + std::to_string(type)});
    return decode_mitigation_options(data, prefix);
}

/// Which GetProcessMitigationPolicy structure the `Flags` DWORD came from.
enum class SelfPolicy { dep, aslr, cfg };

/// Decodes a PROCESS_MITIGATION_{DEP,ASLR,CONTROL_FLOW_GUARD}_POLICY `Flags`
/// DWORD (<winnt.h> layouts) into `self.*` rows; `raw` = Flags in decimal.
inline std::vector<MitigationRow> decode_self_policy(SelfPolicy which, std::uint32_t flags) {
    struct Bit {
        std::string_view name;
        std::uint8_t bit;
    };
    std::vector<Bit> bits;
    switch (which) {
    case SelfPolicy::dep:
        bits = {{"self.dep", 0}}; // Enable; bit1 (DisableAtlThunkEmulation) is not a posture claim
        break;
    case SelfPolicy::aslr:
        bits = {{"self.aslr_bottom_up", 0},
                {"self.aslr_force_relocate", 1},
                {"self.aslr_high_entropy", 2}};
        break;
    case SelfPolicy::cfg:
        bits = {{"self.cfg", 0}, {"self.cfg_export_suppression", 1}, {"self.cfg_strict_mode", 2}};
        break;
    }
    std::vector<MitigationRow> rows;
    for (const auto& b : bits)
        rows.push_back({std::string{b.name}, std::to_string(flags),
                        ((flags >> b.bit) & 1u) ? PolicyState::on : PolicyState::off});
    return rows;
}

/// Win32 error numbers the leg classifies, as plain numbers so this header stays
/// free of <windows.h> (system_hardening_win.cpp static_asserts each against winerror.h).
inline constexpr std::uint32_t kErrorFileNotFound = 2;
inline constexpr std::uint32_t kErrorPathNotFound = 3;
inline constexpr std::uint32_t kErrorAccessDenied = 5;
inline constexpr std::uint32_t kErrorNotSupported = 50;
inline constexpr std::uint32_t kErrorInvalidParameter = 87;

/// Which Win32 call failed. From GetProcessMitigationPolicy, ERROR_NOT_SUPPORTED is the OS
/// saying "this policy does not exist here" (`absent`); ERROR_INVALID_PARAMETER is NOT: every
/// supported target (Windows 10+ x64) implements the DEP, ASLR and CFG classes (the rig capture
/// shows all three succeed), so there it can only mean a malformed call -- a wrong structure
/// size or policy value -- and reads `unreadable` + `<name>:win32_87`. Both are real failures
/// of a registry read.
///
/// `structural_key` is the OPEN of a registry key that exists on every Windows install --
/// `Session Manager\kernel` (rig session A compared that key's full contents before and after
/// on a fresh Windows 11 install: the key was there, only the two mitigation VALUES were not;
/// tests/unit/fixtures/wave8/system_hardening/windows/mitigation_options.hex.provenance.txt).
/// A not-found there is never a legitimate absence (a corrupt hive, a stripped image), so it
/// reads `unreadable` + `<name>:key_missing`, unlike a missing VALUE inside the opened key,
/// which stays `absent`. Same possibility-gate rule as the sibling platform_security plugin's
/// Control\Lsa key.
enum class ReadSource { registry, process_policy, structural_key };

/// How one failed Win32 read is reported. `state` is "absent" when the OS definitively says the
/// thing is not there (`token` empty: no failure, status unaffected) and "unreadable" otherwise
/// (`token` = one `<name>:<cause>` failure token). `access_denied` marks the PERMISSION_DENIED case.
struct ReadFailure {
    std::string_view state;
    std::string token;
    bool access_denied{false};
};

inline ReadFailure classify_win32_failure(std::string_view name, std::uint32_t err,
                                          ReadSource source) {
    const bool not_found = err == kErrorFileNotFound || err == kErrorPathNotFound;
    const bool unsupported = source == ReadSource::process_policy && err == kErrorNotSupported;
    if (not_found && source == ReadSource::structural_key)
        return {"unreadable", std::string{name} + ":key_missing", false};
    if (not_found || unsupported)
        return {"absent", {}, false};
    if (err == kErrorAccessDenied)
        return {"unreadable", std::string{name} + ":access_denied", true};
    return {"unreadable", std::string{name} + ":win32_" + std::to_string(err), false};
}

/// The two registry-backed rows, in emit order: the Session Manager\kernel VALUE each reads and
/// the row name it reports under.
struct RegistryRow {
    std::wstring_view value_name;
    std::string_view row_name;
    std::string_view row_prefix;
};
inline constexpr std::array<RegistryRow, 2> kRegistryRows{{
    {L"MitigationOptions", "mitigation_options", "mitigation."},
    {L"MitigationAuditOptions", "mitigation_audit_options", "mitigation_audit."},
}};

/// One row's failure when the Session Manager\kernel KEY itself could not be opened: every
/// registry row fails with the key's error, classified as ReadSource::structural_key (a
/// not-found key is `key_missing`, never absence). Decided here rather than in the Win32 shell
/// so the structural-key rule is unit-tested at the point the shell consumes it.
struct NamedFailure {
    std::string_view row_name;
    ReadFailure failure;
};
inline std::array<NamedFailure, kRegistryRows.size()> kernel_key_open_failures(std::uint32_t err) {
    std::array<NamedFailure, kRegistryRows.size()> out{};
    for (std::size_t i = 0; i < kRegistryRows.size(); ++i)
        out[i] = {kRegistryRows[i].row_name,
                  classify_win32_failure(kRegistryRows[i].row_name, err,
                                         ReadSource::structural_key)};
    return out;
}

/// A read that failed for a cause the shell detected itself (ERROR_MORE_DATA -> "oversized",
/// a decode_registry_value token such as "type_<n>"): unreadable, one token, never a denial.
inline ReadFailure unreadable_failure(std::string_view name, std::string_view cause) {
    return {"unreadable", std::string{name} + ":" + std::string{cause}, false};
}

/// Hex text -> bytes. Accepts bare hex (whitespace, optional "0x") or a
/// `reg query` line ("    MitigationOptions    REG_BINARY    0022...").
inline Result<std::vector<std::uint8_t>> parse_hex_blob(std::string_view text) {
    if (const auto pos = text.find("REG_BINARY"); pos != std::string_view::npos) {
        text.remove_prefix(pos + std::string_view{"REG_BINARY"}.size());
        if (const auto nl = text.find('\n'); nl != std::string_view::npos)
            text = text.substr(0, nl);
    }
    std::vector<std::uint8_t> out;
    int pending = -1;
    bool any = false;
    auto is_space = [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
    std::size_t i = 0;
    while (i < text.size() && is_space(text[i]))
        ++i;
    if (i + 1 < text.size() && text[i] == '0' && (text[i + 1] == 'x' || text[i + 1] == 'X'))
        i += 2;
    for (; i < text.size(); ++i) {
        const char c = text[i];
        if (is_space(c))
            continue;
        int v = -1;
        if (c >= '0' && c <= '9')
            v = c - '0';
        else if (c >= 'a' && c <= 'f')
            v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
            v = c - 'A' + 10;
        if (v < 0)
            return std::unexpected(DecodeError{"bad_hex"});
        any = true;
        if (pending < 0) {
            pending = v;
        } else {
            out.push_back(static_cast<std::uint8_t>((pending << 4) | v));
            pending = -1;
        }
    }
    if (!any)
        return std::unexpected(DecodeError{"no_hex_digits"});
    if (pending >= 0)
        return std::unexpected(DecodeError{"odd_hex_digits"});
    return out;
}

} // namespace yuzu::system_hardening::mitigation
