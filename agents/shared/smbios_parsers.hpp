// smbios_parsers.hpp -- one shared, bounds-checked SMBIOS structure-table walker and typed
// decoders for structure types 0 (BIOS), 1 (System), 2 (Baseboard), 3 (Chassis), 4 (Processor)
// and 17 (Memory Device). Pure C++: no OS header, no I/O, nothing throws on any input. Each OS leg
// only fetches the bytes (Windows GetSystemFirmwareTable('RSMB'), Linux the DMI table) and hands
// them here.
//
// Two framings, one walk:
//   parse_rsmb(bytes)   the Windows RawSMBIOSData buffer: an 8-byte header (Used20CallingMethod,
//                       SMBIOS Major, Minor, DmiRevision, u32 table Length) then the table;
//   parse_table(bytes)  the headerless structure table (the Linux DMI table, or an RSMB body
//                       with its header already stripped). parse_rsmb validates the header and
//                       calls parse_table on exactly the Length bytes it claims.
//
// Failure model. A PER-TYPE fault (a structure shorter than its type's minimum layout, or a
// string index that runs past its own string set) marks only that entry `Status::malformed`; the
// walk carries on. A FRAMING fault (fewer than 4 bytes left for a structure header, a structure
// Length below 4 or past the end, an unterminated string set) stops the walk at that structure
// and sets SmbiosTable::error (truncated / malformed). Every entry decoded BEFORE the fault is
// kept; nothing after it is decoded. So `error` set means "the walk stopped here": the entries
// are valid but the table was not fully read, and a consumer MUST surface it as a constraint
// token (never present the result as complete). One traversal policy serves every caller.
//
// Unknown and reserved values. Every DSP0134 `unknown` sentinel and every `reserved` value
// decodes to nullopt, never a concrete number (core/thread count byte 0 and word 0 / 0xFFFF, memory
// size 0xFFFF, memory size 0x7FFF in a layout with no Extended Size field, speed 0 and a zero
// extended speed). Strings are RAW (right-trimmed only); string index 0 is nullopt. OEM
// placeholder filtering is the consumer's call (is_placeholder below).
// The walker returns the raw 16 UUID bytes and the RSMB header's major/minor; formatting the UUID
// (byte order is version dependent, SMBIOS >= 2.6 is little-endian for the first three fields)
// is the consumer's job.
//
// Allocation contract. Nothing is allocated beyond the result. Each decoded string field copies
// at most one string out of its OWN structure's string set, so the output is bounded by (the
// largest number of string fields in one structure, 6) x (input bytes) plus the fixed-size
// entries; the entries per vector are capped at kMaxEntriesPerType with a single
// `entry_cap_hit` flag. The INPUT size is the caller's precondition: the walker imposes no
// byte cap of its own (firmware_posture_win.cpp caps the RSMB read at 1 MiB; every new caller
// states and enforces its own cap before calling).
//
// Layouts are decided by the structure's own Length byte, exactly as DSP0134 versions them: a
// field is read only when the Length covers it.
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::shared::smbios {

inline constexpr std::size_t kRsmbHeader = 8; // Used20CallingMethod, Major, Minor, Dmi, u32 Length
inline constexpr std::size_t kMaxEntriesPerType = 256;

inline std::string rtrim(std::string_view s) {
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\n' ||
                          s.back() == '\r' || s.back() == '\0'))
        s.remove_suffix(1);
    return std::string{s};
}

inline std::uint32_t le32(std::span<const std::uint8_t> b, std::size_t o) noexcept {
    return static_cast<std::uint32_t>(b[o]) | static_cast<std::uint32_t>(b[o + 1]) << 8 |
           static_cast<std::uint32_t>(b[o + 2]) << 16 | static_cast<std::uint32_t>(b[o + 3]) << 24;
}
inline std::uint16_t le16(std::span<const std::uint8_t> b, std::size_t o) noexcept {
    return static_cast<std::uint16_t>(b[o] | b[o + 1] << 8);
}

/// 1-based SMBIOS string index into the string-set at [start, end) (end = one past the final
/// double NUL). nullopt = index runs past the set (malformed).
inline std::optional<std::string> smbios_string(std::span<const std::uint8_t> t, std::size_t start,
                                                std::size_t end, unsigned idx) {
    std::size_t p = start;
    for (unsigned i = 1;; ++i) {
        if (p >= end || t[p] == 0) return std::nullopt; // ran out of strings
        std::size_t q = p;
        while (q < end && t[q] != 0) ++q;
        if (i == idx) {
            return rtrim(std::string_view{reinterpret_cast<const char*>(t.data() + p), q - p});
        }
        p = q + 1;
    }
}

enum class Error { truncated, malformed };
enum class Status { absent, ok, malformed };

/// absent = no such structure was reached; ok = decoded; malformed = a structure of this type
/// was reached but its own layout or string indexes were invalid (`data` is then empty).
template <class T> struct Entry {
    Status status = Status::absent;
    T data{};
};

struct Type0 { // BIOS Information
    std::optional<std::string> vendor, version, release_date;
    std::optional<std::uint64_t> rom_size_bytes;
    std::optional<unsigned> bios_major, bios_minor; // System BIOS Major/Minor Release
    std::optional<unsigned> ec_major, ec_minor;     // Embedded Controller Firmware Release
};

struct Type1 { // System Information
    std::optional<std::string> manufacturer, product, version, serial, sku, family;
    std::optional<std::array<std::uint8_t, 16>> uuid; // raw; nullopt when absent, all-00 or all-FF
};

struct Type2 { // Baseboard (Module) Information
    std::optional<std::string> manufacturer, product, version, serial, asset_tag;
};

struct Type3 { // System Enclosure or Chassis
    std::optional<std::string> manufacturer, version, serial, asset_tag;
    unsigned chassis_type = 0; // byte 5 with the chassis-lock bit (bit 7) masked off
};

struct Type4 { // Processor Information
    std::optional<std::string> socket_designation;
    std::array<std::uint8_t, 8> processor_id{};
    unsigned family = 0; // byte 6; Processor Family 2 (word 0x28) when byte 6 is 0xFE
    bool populated = false; // Status byte bit 6 (CPU Socket Populated)
    std::optional<unsigned> core_count, thread_count;
};

struct Type17 { // Memory Device
    std::optional<std::uint64_t> size_bytes; // nullopt = unknown size
    bool populated = false;                  // Size word != 0
    std::optional<std::string> locator, bank_locator, manufacturer, serial, part_number;
    unsigned form_factor = 0;
    unsigned memory_type = 0;
    std::optional<unsigned> speed_mts, configured_speed_mts;
};

struct SmbiosTable {
    std::optional<Error> error;                        // set = the walk stopped at a framing fault
    std::optional<std::pair<unsigned, unsigned>> version; // RSMB header Major, Minor (parse_rsmb only)
    Entry<Type0> bios;
    Entry<Type1> system;
    Entry<Type2> baseboard;
    Entry<Type3> chassis;
    std::vector<Entry<Type4>> processors;
    std::vector<Entry<Type17>> memory_devices;
    bool entry_cap_hit = false; // a vector reached kMaxEntriesPerType and further entries were dropped
};

namespace detail {

// One structure under the walk: its formatted area is t[off, off+len), its string set
// [sstart, send). A field is addressed by its offset within the structure.
struct View {
    std::span<const std::uint8_t> t;
    std::size_t off, len, sstart, send;

    unsigned u8(std::size_t o) const noexcept { return t[off + o]; }
    unsigned u16(std::size_t o) const noexcept { return le16(t, off + o); }
    std::uint32_t u32(std::size_t o) const noexcept { return le32(t, off + o); }

    // String field at `at`: index 0 -> nullopt (no string), index past the set -> false.
    bool str(std::size_t at, std::optional<std::string>& out) const {
        const unsigned idx = u8(at);
        if (idx == 0) return true;
        auto s = smbios_string(t, sstart, send, idx);
        if (!s) return false;
        out = std::move(*s);
        return true;
    }
};

inline Entry<Type0> decode_type0(const View& v) {
    if (v.len < 0x12) return {Status::malformed, {}};
    Type0 d;
    if (!v.str(4, d.vendor) || !v.str(5, d.version) || !v.str(8, d.release_date))
        return {Status::malformed, {}};
    const unsigned rom = v.u8(9);
    if (rom != 0xFF) {
        d.rom_size_bytes = static_cast<std::uint64_t>(rom + 1) * 64ull * 1024ull;
    } else if (v.len >= 0x1A) { // SMBIOS 3.1+: Extended BIOS ROM Size, bits 15:14 = unit
        const std::uint16_t ext = static_cast<std::uint16_t>(v.u16(0x18));
        const unsigned unit = ext >> 14;
        const std::uint64_t n = ext & 0x3FFFu;
        if (unit == 0) d.rom_size_bytes = n * 1024ull * 1024ull;
        else if (unit == 1) d.rom_size_bytes = n * 1024ull * 1024ull * 1024ull;
        // units 2/3 are reserved: leave unset (unmodelled, not guessed)
    }
    if (v.len >= 0x18) { // SMBIOS 2.4+: 0xFF in a release byte = not specified
        auto rel = [&](std::size_t at) -> std::optional<unsigned> {
            const unsigned b = v.u8(at);
            return b == 0xFF ? std::nullopt : std::optional<unsigned>{b};
        };
        d.bios_major = rel(0x14);
        d.bios_minor = rel(0x15);
        d.ec_major = rel(0x16);
        d.ec_minor = rel(0x17);
    }
    return {Status::ok, std::move(d)};
}

inline Entry<Type1> decode_type1(const View& v) {
    if (v.len < 0x08) return {Status::malformed, {}};
    Type1 d;
    if (!v.str(4, d.manufacturer) || !v.str(5, d.product) || !v.str(6, d.version) ||
        !v.str(7, d.serial))
        return {Status::malformed, {}};
    if (v.len >= 0x19) { // SMBIOS 2.1+: UUID
        std::array<std::uint8_t, 16> u{};
        bool all00 = true, allff = true;
        for (std::size_t i = 0; i < 16; ++i) {
            u[i] = static_cast<std::uint8_t>(v.u8(8 + i));
            all00 = all00 && u[i] == 0x00;
            allff = allff && u[i] == 0xFF;
        }
        if (!all00 && !allff) d.uuid = u; // all-00 = not set, all-FF = not present
    }
    if (v.len >= 0x1B && (!v.str(0x19, d.sku) || !v.str(0x1A, d.family))) // SMBIOS 2.4+
        return {Status::malformed, {}};
    return {Status::ok, std::move(d)};
}

inline Entry<Type2> decode_type2(const View& v) {
    if (v.len < 0x08) return {Status::malformed, {}};
    Type2 d;
    if (!v.str(4, d.manufacturer) || !v.str(5, d.product) || !v.str(6, d.version) ||
        !v.str(7, d.serial))
        return {Status::malformed, {}};
    if (v.len >= 0x09 && !v.str(8, d.asset_tag)) return {Status::malformed, {}};
    return {Status::ok, std::move(d)};
}

inline Entry<Type3> decode_type3(const View& v) {
    if (v.len < 0x09) return {Status::malformed, {}};
    Type3 d;
    if (!v.str(4, d.manufacturer) || !v.str(6, d.version) || !v.str(7, d.serial) ||
        !v.str(8, d.asset_tag))
        return {Status::malformed, {}};
    d.chassis_type = v.u8(5) & 0x7Fu;
    return {Status::ok, std::move(d)};
}

// DSP0134 7.5.6-7.5.8: a count byte of 0 is unknown; 0xFF defers to the 2-byte count, whose 0
// (unknown) and 0xFFFF (reserved) are not counts either. A layout too short for the word = unknown.
inline std::optional<unsigned> processor_count(const View& v, std::size_t byte_at, std::size_t word_at) {
    if (v.len < byte_at + 1) return std::nullopt;
    const unsigned b = v.u8(byte_at);
    if (b == 0) return std::nullopt;
    if (b != 0xFF) return b;
    if (v.len < word_at + 2) return std::nullopt;
    const unsigned w = v.u16(word_at);
    if (w == 0 || w == 0xFFFF) return std::nullopt;
    return w;
}

inline Entry<Type4> decode_type4(const View& v) {
    if (v.len < 0x1A) return {Status::malformed, {}};
    Type4 d;
    if (!v.str(4, d.socket_designation)) return {Status::malformed, {}};
    for (std::size_t i = 0; i < 8; ++i) d.processor_id[i] = static_cast<std::uint8_t>(v.u8(8 + i));
    d.family = v.u8(6);
    if (d.family == 0xFE && v.len >= 0x2A) d.family = v.u16(0x28); // Processor Family 2
    d.populated = (v.u8(0x18) & 0x40u) != 0;
    d.core_count = processor_count(v, 0x23, 0x2A);
    d.thread_count = processor_count(v, 0x25, 0x2E);
    return {Status::ok, std::move(d)};
}

// DSP0134 7.18.14: speed word 0 = unknown, 0xFFFF = see the extended dword (bit 31 reserved).
inline std::optional<unsigned> memory_speed(const View& v, std::size_t word_at, std::size_t ext_at) {
    if (v.len < word_at + 2) return std::nullopt;
    const unsigned w = v.u16(word_at);
    if (w == 0) return std::nullopt;
    if (w != 0xFFFF) return w;
    if (v.len < ext_at + 4) return std::nullopt;
    const std::uint32_t ext = v.u32(ext_at) & 0x7FFFFFFFu;
    if (ext == 0) return std::nullopt;
    return ext;
}

inline Entry<Type17> decode_type17(const View& v) {
    if (v.len < 0x15) return {Status::malformed, {}};
    Type17 d;
    if (v.len >= 0x1B &&
        (!v.str(0x17, d.manufacturer) || !v.str(0x18, d.serial) || !v.str(0x1A, d.part_number)))
        return {Status::malformed, {}};
    if (!v.str(0x10, d.locator) || !v.str(0x11, d.bank_locator)) return {Status::malformed, {}};
    const unsigned size = v.u16(0x0C);
    d.populated = size != 0;
    if (size == 0) d.size_bytes = 0;
    else if (size == 0xFFFF) d.size_bytes = std::nullopt; // unknown
    else if (size == 0x7FFF) {                            // "see Extended Size" (SMBIOS 2.7+, MiB)
        if (v.len >= 0x20) {
            const std::uint64_t mib = v.u32(0x1C) & 0x7FFFFFFFu;
            if (mib != 0) d.size_bytes = mib * 1024ull * 1024ull;
        } // else the layout has no Extended Size dword: the capacity is unknown, never 32767 MiB
    } else if (size & 0x8000u) d.size_bytes = static_cast<std::uint64_t>(size & 0x7FFFu) * 1024ull; // KiB
    else d.size_bytes = static_cast<std::uint64_t>(size) * 1024ull * 1024ull;                       // MiB
    d.form_factor = v.u8(0x0E);
    if (v.len >= 0x13) d.memory_type = v.u8(0x12);
    d.speed_mts = memory_speed(v, 0x15, 0x54);
    d.configured_speed_mts = memory_speed(v, 0x20, 0x58);
    return {Status::ok, std::move(d)};
}

// The cap test runs BEFORE the decoder, so a structure past kMaxEntriesPerType is never decoded
// (its strings are never copied): the banner's allocation contract. Pinned by
// tests/unit/test_smbios_alloc_budget.cpp.
template <class T, class F>
void push_capped(std::vector<Entry<T>>& vec, bool& cap_hit, const View& v, F decode) {
    if (vec.size() >= kMaxEntriesPerType) {
        cap_hit = true;
        return;
    }
    vec.push_back(decode(v));
}

} // namespace detail

/// Walks a headerless SMBIOS structure table. See the banner for the failure model.
[[nodiscard]] inline SmbiosTable parse_table(std::span<const std::uint8_t> t) {
    SmbiosTable out;
    std::size_t off = 0;
    while (off < t.size()) {
        if (t.size() - off < 4) {
            out.error = Error::truncated;
            return out;
        }
        const std::uint8_t type = t[off];
        const std::size_t len = t[off + 1];
        if (len < 4) {
            out.error = Error::malformed;
            return out;
        }
        if (t.size() - off < len) {
            out.error = Error::truncated;
            return out;
        }
        const std::size_t sstart = off + len;
        // String-set: NUL-terminated strings ended by one extra NUL (two NULs when empty).
        std::size_t p = sstart;
        for (;; ++p) {
            if (p + 1 >= t.size()) {
                out.error = Error::truncated;
                return out;
            }
            if (t[p] == 0 && t[p + 1] == 0) break;
        }
        const std::size_t send = p + 2;
        if (type == 127) return out; // end-of-table marker
        const detail::View v{t, off, len, sstart, send};
        switch (type) {
        case 0: if (out.bios.status == Status::absent) out.bios = detail::decode_type0(v); break;
        case 1: if (out.system.status == Status::absent) out.system = detail::decode_type1(v); break;
        case 2:
            if (out.baseboard.status == Status::absent) out.baseboard = detail::decode_type2(v);
            break;
        case 3: if (out.chassis.status == Status::absent) out.chassis = detail::decode_type3(v); break;
        case 4: detail::push_capped(out.processors, out.entry_cap_hit, v, detail::decode_type4); break;
        case 17:
            detail::push_capped(out.memory_devices, out.entry_cap_hit, v, detail::decode_type17);
            break;
        default: break; // every other type is stepped over
        }
        off = send;
    }
    return out;
}

/// Walks a Windows RSMB buffer (GetSystemFirmwareTable('RSMB')): validates the 8-byte
/// RawSMBIOSData header (the table Length it claims must fit the buffer), records its SMBIOS
/// major/minor and walks exactly the claimed table bytes.
[[nodiscard]] inline SmbiosTable parse_rsmb(std::span<const std::uint8_t> raw) {
    SmbiosTable out;
    if (raw.size() < kRsmbHeader) {
        out.error = Error::truncated;
        return out;
    }
    const std::uint32_t claimed = le32(raw, 4);
    if (raw.size() - kRsmbHeader < claimed) {
        out.error = Error::truncated;
        return out;
    }
    out = parse_table(raw.subspan(kRsmbHeader, claimed));
    out.version = std::pair<unsigned, unsigned>{raw[1], raw[2]};
    return out;
}

/// The OEM filler strings firmware ships instead of real data, matched whole (see is_placeholder).
/// Deliberately excludes "Standard", "Default", "Family", "Empty" and "NULL": each is a plausible
/// real value, and a false positive blanks it. Exposed so the test pins the exact table.
inline constexpr std::array<std::string_view, 26> kPlaceholders{
    "Default string", "To Be Filled By O.E.M.", "None", "Not Specified", "Not Available",
    "N/A", "Unknown", "Undefined", "System Serial Number", "System Product Name",
    "System manufacturer", "System Version", "Base Board", "Chassis Serial Number",
    "Chassis Version", "Chassis Manufacture", "Asset Tag", "No Asset Tag",
    "No Asset Information", "Not Applicable", "OEM", "0123456789", "1234567890", "SKU",
    "x.x", "Type1ProductConfigId"};

/// True when `s` (right-trimmed, ASCII case-insensitive) is empty or one of kPlaceholders.
/// The walker returns raw strings; legs call this.
[[nodiscard]] inline bool is_placeholder(std::string_view s) {
    const std::string t = rtrim(s);
    if (t.empty()) return true;
    auto lower = [](char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; };
    for (std::string_view p : kPlaceholders)
        if (std::ranges::equal(p, t, {}, lower, lower)) return true;
    return false;
}

} // namespace yuzu::shared::smbios
