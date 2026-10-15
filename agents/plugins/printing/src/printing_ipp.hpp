// printing_ipp.hpp — a minimal, PURE RFC 8010 (Internet Printing Protocol)
// binary encoder/decoder, built from scratch for this plugin: no IPP codec
// existed anywhere in the tree before this file, and vcpkg.json has no cups
// entry (verified) — libcups is deliberately not adopted (see
// agents/plugins/printing/src/printing_plugin.cpp's file banner).
//
// Scope is intentionally narrow: only the attribute-group/value shapes this
// plugin's four operations (CUPS-Get-Printers, CUPS-Get-Default, Get-Jobs,
// Cancel-Job) actually send and receive. No I/O, no OS headers — every
// symbol here is usable on every host, including the Windows leg's build
// (which never issues an IPP request, but shares the parsers header's
// dependency on this file's tag constants for readability).
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::printing::ipp {

// ── RFC 8010 §3.5.1 attribute-group delimiter tags ─────────────────────────
inline constexpr uint8_t kTagOperationAttributes = 0x01;
inline constexpr uint8_t kTagJobAttributes = 0x02;
inline constexpr uint8_t kTagEndOfAttributes = 0x03;
inline constexpr uint8_t kTagPrinterAttributes = 0x04;
inline constexpr uint8_t kTagUnsupportedAttributes = 0x05;

// ── RFC 8010 §3.5.2 value tags this codec knows how to encode ──────────────
inline constexpr uint8_t kTagInteger = 0x21;
inline constexpr uint8_t kTagEnum = 0x23;
inline constexpr uint8_t kTagUri = 0x45;
inline constexpr uint8_t kTagKeyword = 0x44;
inline constexpr uint8_t kTagCharset = 0x47;
inline constexpr uint8_t kTagNaturalLanguage = 0x48;
inline constexpr uint8_t kTagNameWithoutLanguage = 0x42;

// ── Operation ids this plugin issues (RFC 8010 §3.1.1 range + CUPS's own
// vendor-extension range, RFC 8010 doesn't allocate CUPS-Get-Printers /
// CUPS-Get-Default — both are longstanding CUPS de-facto operation ids) ────
inline constexpr uint16_t kCupsGetPrinters = 0x4002;
inline constexpr uint16_t kCupsGetDefault = 0x4001;
inline constexpr uint16_t kGetJobs = 0x000A;
inline constexpr uint16_t kCancelJob = 0x0008;

inline constexpr uint16_t kVersion = 0x0200; // IPP/2.0, RFC 8010 §3.1.8

/// One IPP attribute: a tag, a name, and one-or-more values (RFC 8010's
/// "additional value" continuation collapses onto this same struct — see
/// decode()'s handling of an empty-name value below).
struct Attr {
    uint8_t tag = 0;
    std::string name;
    std::vector<std::string> values;
};

/// One decoded/encoded IPP message. `op_or_status` is the operation-id on a
/// request, the status-code on a response — the wire position is identical
/// (RFC 8010 §3.1.1/§3.1.6), so one field serves both directions, same as
/// the RFC's own "operation-id or status-code" framing.
struct Message {
    uint16_t version = kVersion;
    uint16_t op_or_status = 0;
    uint32_t request_id = 0;
    std::vector<std::pair<uint8_t, std::vector<Attr>>> groups;
};

/// One operation-attribute this plugin encodes into a request, beyond the
/// two mandatory attributes-charset/attributes-natural-language attributes
/// encode_request() always sends first. `additional_values`, when non-empty,
/// encodes a `1setOf` attribute (e.g. `requested-attributes`): RFC 8010
/// §3.5.2's "additional value" continuation — `value` is written as a
/// normal tag+name+value triple, then each entry of `additional_values` is
/// written as tag + a zero-length name + value, exactly what decode()
/// already expects on the way back in (see its empty-name handling).
struct OperationAttr {
    uint8_t tag = 0;
    std::string name;
    std::string value;
    std::vector<std::string> additional_values;
};

namespace detail {

inline void put_u16(std::string& out, uint16_t v) {
    out.push_back(static_cast<char>((v >> 8) & 0xFF));
    out.push_back(static_cast<char>(v & 0xFF));
}

inline void put_u32(std::string& out, uint32_t v) {
    out.push_back(static_cast<char>((v >> 24) & 0xFF));
    out.push_back(static_cast<char>((v >> 16) & 0xFF));
    out.push_back(static_cast<char>((v >> 8) & 0xFF));
    out.push_back(static_cast<char>(v & 0xFF));
}

inline void put_attr(std::string& out, uint8_t tag, std::string_view name, std::string_view value) {
    out.push_back(static_cast<char>(tag));
    put_u16(out, static_cast<uint16_t>(name.size()));
    out.append(name);
    put_u16(out, static_cast<uint16_t>(value.size()));
    out.append(value);
}

} // namespace detail

/// RFC 8010 §3.5.2: the wire value for an `integer`/`enum` (0x21/0x23)
/// attribute is 4 raw bytes, big-endian two's complement — never decimal
/// ASCII text. Callers building an `OperationAttr` with `kTagInteger` MUST
/// pass this encoding as the value (see encode_request's Cancel-Job
/// `job-id` caller in printing_plugin.cpp), and `printing_parsers.hpp`'s
/// `detail::first_int` decodes a value the same way on the way back in.
[[nodiscard]] inline std::string encode_int32(int32_t v) {
    std::string out;
    detail::put_u32(out, static_cast<uint32_t>(v));
    return out;
}

/// Encodes one IPP request: version 0x0200, `op`, `request_id`, then a
/// single operation-attributes group (0x01) with attributes-charset=utf-8
/// and attributes-natural-language=en FIRST (RFC 8010 §3.1.4.1 — every IPP
/// request's two mandatory leading operation attributes), followed by
/// `operation_attrs` in the order given, then end-of-attributes (0x03).
/// This plugin never sends a job-attributes or printer-attributes group on
/// a request, so no group-selection parameter is needed.
///
/// Returns an EMPTY string (a request that must not be sent) when any
/// attribute name or value exceeds the 16-bit IPP length prefix. Writing the
/// truncated length and then appending the whole value would let the peer
/// parse the excess bytes as further attributes -- a caller-controlled value
/// could inject attributes into the request.
[[nodiscard]] inline std::string encode_request(uint16_t op, uint32_t request_id,
                                                 const std::vector<OperationAttr>& operation_attrs) {
    constexpr std::size_t kMaxIppLength = 0xFFFF;
    for (const auto& a : operation_attrs) {
        if (a.name.size() > kMaxIppLength || a.value.size() > kMaxIppLength)
            return {};
        for (const auto& extra : a.additional_values) {
            if (extra.size() > kMaxIppLength)
                return {};
        }
    }
    std::string out;
    detail::put_u16(out, kVersion);
    detail::put_u16(out, op);
    detail::put_u32(out, request_id);

    out.push_back(static_cast<char>(kTagOperationAttributes));
    detail::put_attr(out, kTagCharset, "attributes-charset", "utf-8");
    detail::put_attr(out, kTagNaturalLanguage, "attributes-natural-language", "en");
    for (const auto& a : operation_attrs) {
        detail::put_attr(out, a.tag, a.name, a.value);
        for (const auto& extra : a.additional_values) {
            out.push_back(static_cast<char>(a.tag));
            detail::put_u16(out, 0); // zero-length name -> additional-value continuation
            detail::put_u16(out, static_cast<uint16_t>(extra.size()));
            out.append(extra);
        }
    }

    out.push_back(static_cast<char>(kTagEndOfAttributes));
    return out;
}

/// Decodes an IPP message from raw bytes. Every read is bounds-checked
/// against `bytes.size()` before it happens — a truncated/malformed stream
/// returns `std::nullopt`, never reads or writes past the span (no UB, no
/// out-of-bounds access, regardless of how the bytes were produced).
///
/// Recognises attribute-group delimiter tags 0x01/0x02/0x04 (0x05 —
/// unsupported-attributes — is also accepted as a group opener since a
/// Get-Jobs/CUPS-Get-Printers response may legally include one) and the
/// additional-value continuation (RFC 8010 §3.5.2: a value whose two-byte
/// name-length is 0 belongs to the immediately preceding attribute in the
/// current group). Decoding stops cleanly at 0x03 (end-of-attributes) and
/// returns the message built so far; running off the end of the buffer
/// without ever seeing 0x03 is truncation and returns `std::nullopt`.
[[nodiscard]] inline std::optional<Message> decode(std::span<const uint8_t> bytes) {
    if (bytes.size() < 8)
        return std::nullopt;

    const auto u16 = [&](std::size_t at) -> uint16_t {
        return static_cast<uint16_t>((static_cast<unsigned>(bytes[at]) << 8) | bytes[at + 1]);
    };
    const auto u32 = [&](std::size_t at) -> uint32_t {
        return (static_cast<uint32_t>(bytes[at]) << 24) | (static_cast<uint32_t>(bytes[at + 1]) << 16) |
               (static_cast<uint32_t>(bytes[at + 2]) << 8) | static_cast<uint32_t>(bytes[at + 3]);
    };

    Message msg;
    msg.version = u16(0);
    msg.op_or_status = u16(2);
    msg.request_id = u32(4);
    std::size_t pos = 8;

    std::pair<uint8_t, std::vector<Attr>>* current_group = nullptr;

    while (pos < bytes.size()) {
        const uint8_t tag = bytes[pos];
        ++pos;

        if (tag == kTagEndOfAttributes)
            return msg;

        if (tag == kTagOperationAttributes || tag == kTagJobAttributes ||
            tag == kTagPrinterAttributes || tag == kTagUnsupportedAttributes) {
            msg.groups.emplace_back(tag, std::vector<Attr>{});
            current_group = &msg.groups.back();
            continue;
        }

        // Anything else is a value tag within the currently-open group. A
        // value tag before any group has opened is malformed input.
        if (!current_group)
            return std::nullopt;

        if (pos + 2 > bytes.size())
            return std::nullopt;
        const uint16_t name_len = u16(pos);
        pos += 2;
        if (pos + name_len > bytes.size())
            return std::nullopt;
        std::string name(reinterpret_cast<const char*>(bytes.data() + pos), name_len);
        pos += name_len;

        if (pos + 2 > bytes.size())
            return std::nullopt;
        const uint16_t value_len = u16(pos);
        pos += 2;
        if (pos + value_len > bytes.size())
            return std::nullopt;
        std::string value(reinterpret_cast<const char*>(bytes.data() + pos), value_len);
        pos += value_len;

        if (name.empty()) {
            // Additional-value continuation — appends to the previous
            // attribute in this group. A continuation with nothing to
            // continue is malformed.
            if (current_group->second.empty())
                return std::nullopt;
            current_group->second.back().values.push_back(std::move(value));
        } else {
            Attr attr;
            attr.tag = tag;
            attr.name = std::move(name);
            attr.values.push_back(std::move(value));
            current_group->second.push_back(std::move(attr));
        }
    }

    // Ran off the end of the buffer without ever seeing end-of-attributes —
    // truncated, never silently accepted as complete.
    return std::nullopt;
}

} // namespace yuzu::printing::ipp
