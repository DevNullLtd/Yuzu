#pragma once

// Install-row attributes: the validated `key=value` field carried in wire slot 14 of a blob-v3
// installed-software `+` record (ADR-0016, SAM-46). Both ends of the wire include THIS header,
// the agent writer (installed_software_v3.cpp, sync_source_installed_software.cpp) and the
// server parser (inventory_blob_v3.hpp), so the key table and the canonical form cannot drift:
// the field is part of the byte form the v3 section hash is taken over.
//
// CANONICAL FORM. `key=value` pairs joined by `;`, keys in strictly ascending byte order, each
// key at most once, no trailing `;`, the whole field at most kMaxAttributesLen bytes. The empty
// string is the canonical "no attributes" and is what the slot carried before this field existed
// (reserved, always empty), so a row without attributes hashes to the bytes it always did. A
// value holds no `;`, no `=` and no control byte (0x00-0x1F and 0x7F, which covers NUL and the
// wire separators 0x1E and 0x1F). Every key is in the closed table below and its value passes
// that key's validator.
//
// ADDING A KEY (SAM-45b and later): one row in kAttributeKeys, in name order, with a validator and
// a golden vector in the agent and server tests. No wire change, no migration, no parser change.
// A new key is a contract change on both ends of the wire: land the table row, the validator and
// the golden together. With a second key, also add a make_attributes test case: a value carrying
// `;<that key>=<valid value>` must be refused.
//   - Validator bytes: a validator must reject every byte the canonical form uses as a separator
//     (`;`, `=`) and every byte the field step would strip, so it accepts only bytes the field
//     step leaves unchanged. The agent's clamp_field strips 0x1F, 0x1E and NUL (after scrubbing
//     invalid UTF-8) and the server's scrub-and-clamp strips nothing, so a value holding one would
//     read differently on the two ends of the hash. The screen in canonical_attributes and
//     make_attributes already refuses these bytes in every value; keep it ahead of any validator.
//   - Key side: a key name is joined into the field unescaped, so a name holds no `;`, `=` or
//     control byte, and make_attributes joins the caller's key before it checks it (a pair whose
//     key carries `;` or `=` could read back as two). With one key the table lookup in
//     canonical_attributes refuses that. With a second key, make_attributes must look every key
//     up in kAttributeKeys first (tracked in #8361).
//
// Pure: std only, no I/O, no store or wire types, so it stays inside the common/include firewall.

#include <algorithm>
#include <array>
#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::install_attrs {

/// Whole-field cap (bytes). Equal to the v3 per-field cap (kV3MaxFieldLen), so the server's
/// per-field clamp never alters a value this header accepted. The equality is static_assert'ed
/// beside each kV3MaxFieldLen (agent and server).
inline constexpr std::size_t kMaxAttributesLen = 1024;

namespace detail {

[[nodiscard]] constexpr bool is_upper_hex(char c) noexcept {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F');
}

/// `{8-4-4-4-12}`: braces and hyphens in place, every other byte upper-case hex.
[[nodiscard]] constexpr bool is_upgrade_code(std::string_view v) noexcept {
    if (v.size() != 38 || v.front() != '{' || v.back() != '}')
        return false;
    for (std::size_t i = 1; i + 1 < v.size(); ++i) {
        const bool hyphen = i == 9 || i == 14 || i == 19 || i == 24;
        if (hyphen ? v[i] != '-' : !is_upper_hex(v[i]))
            return false;
    }
    return true;
}

/// A value byte the wire cannot carry: the pair and key separators and every control byte
/// (0x00-0x1F and 0x7F, which covers NUL and the wire separators 0x1E and 0x1F).
[[nodiscard]] constexpr bool is_forbidden_value_byte(char c) noexcept {
    const auto u = static_cast<unsigned char>(c);
    return c == ';' || c == '=' || u < 0x20 || u == 0x7F;
}

} // namespace detail

struct AttributeKey {
    std::string_view name;
    bool (*valid)(std::string_view value) noexcept;
};

/// The closed key table, strictly ascending by name (static_assert below).
inline constexpr std::array<AttributeKey, 1> kAttributeKeys{{
    {"upgrade_code", detail::is_upgrade_code},
}};

[[nodiscard]] constexpr bool keys_sorted_and_unique() noexcept {
    for (std::size_t i = 1; i < kAttributeKeys.size(); ++i) {
        if (!(kAttributeKeys[i - 1].name < kAttributeKeys[i].name))
            return false;
    }
    return true;
}
static_assert(keys_sorted_and_unique(), "kAttributeKeys must be strictly ascending by name");

/// `raw` when it is already in canonical form (see the file comment), else nullopt. The empty
/// string is canonical. Idempotent: canonical_attributes(*canonical_attributes(x)) == x.
[[nodiscard]] inline std::optional<std::string> canonical_attributes(std::string_view raw) {
    if (raw.size() > kMaxAttributesLen)
        return std::nullopt;
    if (raw.empty())
        return std::string{};
    std::string_view prev_key;
    for (std::size_t pos = 0;;) {
        const std::size_t end = raw.find(';', pos);
        const std::string_view pair = raw.substr(pos, end == raw.npos ? raw.npos : end - pos);
        const std::size_t eq = pair.find('=');
        if (eq == pair.npos || eq == 0 || eq + 1 == pair.size())
            return std::nullopt; // no `=`, an empty key or value, `;;`, a leading or trailing `;`
        const std::string_view key = pair.substr(0, eq);
        const std::string_view value = pair.substr(eq + 1);
        if (!prev_key.empty() && !(prev_key < key))
            return std::nullopt; // out of order or a duplicate
        if (std::ranges::any_of(value, detail::is_forbidden_value_byte))
            return std::nullopt;
        const auto def = std::ranges::find(kAttributeKeys, key, &AttributeKey::name);
        if (def == kAttributeKeys.end() || !def->valid(value))
            return std::nullopt; // unknown key or a value its validator refuses
        prev_key = key;
        if (end == raw.npos)
            return std::string(raw);
        pos = end + 1;
    }
}

/// The value of `key` in a canonical attribute field, or an empty view when it carries none.
/// A view into `canonical`.
[[nodiscard]] inline std::string_view attribute_value(std::string_view canonical,
                                                      std::string_view key) noexcept {
    std::size_t pos = 0;
    while (pos < canonical.size()) {
        std::size_t end = canonical.find(';', pos);
        if (end == std::string_view::npos)
            end = canonical.size();
        const std::string_view pair = canonical.substr(pos, end - pos);
        const std::size_t eq = pair.find('=');
        if (eq != std::string_view::npos && pair.substr(0, eq) == key)
            return pair.substr(eq + 1);
        pos = end + 1;
    }
    return {};
}

/// The canonical field for `pairs` (any order), or nullopt when a key is unknown or repeated or a
/// value fails its validator. Empty `pairs` give the empty field.
[[nodiscard]] inline std::optional<std::string>
make_attributes(std::span<const std::pair<std::string_view, std::string_view>> pairs) {
    std::vector<std::pair<std::string_view, std::string_view>> sorted(pairs.begin(), pairs.end());
    std::ranges::sort(sorted);
    std::string out;
    for (const auto& [key, value] : sorted) {
        // Checked per pair, before the join: a value carrying `;` or `=` would read back as a
        // pair the caller never passed.
        if (std::ranges::any_of(value, detail::is_forbidden_value_byte))
            return std::nullopt;
        if (!out.empty())
            out += ';';
        out += key;
        out += '=';
        out += value;
    }
    return canonical_attributes(out);
}

} // namespace yuzu::install_attrs
