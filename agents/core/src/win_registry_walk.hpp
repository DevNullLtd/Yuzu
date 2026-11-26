#pragma once

/**
 * win_registry_walk.hpp -- every decision of the agent-core HKLM registry read: the request caps,
 * the access mask, the child walk, the raw value read and the value decode. Internal to
 * agent-core. Portable (no Windows header), so every host tests it with a fake Ops;
 * win_registry_read.cpp supplies the Ops, one Reg*W call per member.
 *
 * Ops, each member answering the Win32 error code of its call (0 on success):
 *   open_base(subkey, access)             open HKLM\subkey; query_value now reads it
 *   child_name(index, name)               the name of the base key's child at `index`
 *   open_child(name, access)              open that child; query_value now reads it
 *   query_value(name, type, data, size)   RegQueryValueExW: a null `data` asks for the size,
 *                                         otherwise `size` is the capacity in and the length out
 */

#include <yuzu/agent/win_registry_read.hpp>

#include "binary_header_pe.hpp"   // yuzu::shared::binary_header::utf16_to_utf8 (agents/shared)
#include "user_profile_model.hpp" // yuzu::profiles::multi_sz_records, kReg* (agents/shared)

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::agent::win::detail {

// Win32 values, fixed by the ABI; win_registry_read.cpp asserts them against the SDK.
inline constexpr std::uint32_t kErrorInvalidData = 13;
inline constexpr std::uint32_t kErrorInvalidParameter = 87;
inline constexpr std::uint32_t kErrorMoreData = 234;
inline constexpr std::uint32_t kErrorNoMoreItems = 259;
inline constexpr std::uint32_t kKeyRead = 0x20019;
inline constexpr std::uint32_t kKeyWow64Key64 = 0x0100;
inline constexpr std::uint32_t kKeyWow64Key32 = 0x0200;

/// Re-reads of a value that grows between its size query and its data query.
inline constexpr int kMaxRegGrowthRetries = 3;

/// One value's data, decoded. Nothing past `data` is read, terminated or not.
inline RegValue decode_reg_value(std::string name, std::uint32_t type,
                                 std::span<const std::uint8_t> data) {
    using yuzu::shared::binary_header::utf16_to_utf8;
    RegValue value;
    value.name = std::move(name);
    value.present = true;
    value.type = type;
    // UTF-16LE units; an odd trailing byte is dropped.
    const auto units = [data] {
        std::u16string out(data.size() / 2, u'\0');
        for (std::size_t i = 0; i < out.size(); ++i)
            out[i] = static_cast<char16_t>(data[2 * i] | (data[2 * i + 1] << 8));
        return out;
    };
    switch (type) {
    case yuzu::profiles::kRegSz:
    case yuzu::profiles::kRegExpandSz: {
        const std::u16string text = units();
        value.text = utf16_to_utf8(std::u16string_view{text}.substr(0, text.find(u'\0')));
        break;
    }
    case yuzu::profiles::kRegMultiSz: {
        const std::u16string text = units();
        for (const auto& [offset, length] : yuzu::profiles::multi_sz_records(text)) {
            if (!value.text.empty())
                value.text += '\n';
            value.text += utf16_to_utf8(std::u16string_view{text}.substr(offset, length));
        }
        break;
    }
    case yuzu::profiles::kRegDword:
    case yuzu::profiles::kRegQword: {
        const std::size_t width = type == yuzu::profiles::kRegDword ? 4 : 8;
        if (data.size() < width) {
            value.win_error = kErrorInvalidData;
            break;
        }
        for (std::size_t i = 0; i < width; ++i) // little-endian
            value.number |= std::uint64_t{data[i]} << (8 * i);
        break;
    }
    default:
        value.bytes.assign(data.begin(), data.end());
        break;
    }
    return value;
}

struct RawRegValue {
    std::uint32_t rc = 0;
    std::uint32_t type = 0;
    std::vector<std::uint8_t> data; ///< empty unless rc == 0
};

/// A size query, the per-value cap applied to the queried size before any allocation, then the
/// data query. A value that grew in between is sized and read again. rc 234: the value is over the
/// cap, or still growing after the re-reads.
template <typename Ops> RawRegValue read_raw_value(Ops& ops, const std::string& name) {
    RawRegValue out;
    std::uint32_t size = 0;
    for (int attempt = 0; attempt <= kMaxRegGrowthRetries; ++attempt) {
        out.rc = ops.query_value(name, out.type, nullptr, size);
        if (out.rc != 0)
            break;
        if (size > kMaxRegValueBytes) {
            out.rc = kErrorMoreData;
            break;
        }
        // At least one byte: a null data pointer would make this a second size query.
        out.data.resize(std::max<std::size_t>(size, 1));
        size = static_cast<std::uint32_t>(out.data.size());
        out.rc = ops.query_value(name, out.type, out.data.data(), size);
        if (out.rc != kErrorMoreData)
            break;
    }
    out.data.resize(out.rc == 0 ? size : 0);
    return out;
}

/// Appends the requested values of the key `ops` has open to `entry`. `total` counts the value
/// data of the whole request. False when the total cap ends the walk.
template <typename Ops>
bool walk_values(const RegRequest& request, Ops& ops, std::size_t& total, RegKeyValues& entry,
                 bool& truncated) {
    for (const auto& name : request.value_names) {
        const RawRegValue raw = read_raw_value(ops, name);
        RegValue value;
        if (raw.rc == 0) {
            if (raw.data.size() > kMaxRegTotalBytes - total) {
                truncated = true;
                return false;
            }
            total += raw.data.size();
            value = decode_reg_value(name, raw.type, raw.data);
        } else {
            value.name = name;
            value.win_error = raw.rc;
            if (raw.rc == kErrorMoreData) { // it exists, but its data is not returned
                value.present = true;
                value.type = raw.type;
                truncated = true;
            }
        }
        entry.values.push_back(std::move(value));
    }
    return true;
}

/// The whole read of one request. `status` is left to the bounded driver.
template <typename Ops> RegRead walk_registry(const RegRequest& request, Ops& ops) {
    RegRead out;
    // A name holding a NUL would be cut at the Win32 call and read something else.
    const auto has_nul = [](const auto& name) {
        return name.find('\0') != name.npos;
    };
    if (request.hklm_subkey.empty() || request.value_names.size() > kMaxRegValueNames ||
        has_nul(request.hklm_subkey) || std::ranges::any_of(request.value_names, has_nul)) {
        out.win_error = kErrorInvalidParameter;
        return out;
    }
    // Read-only, in the 64-bit view unless the 32-bit one is asked for.
    const std::uint32_t access = kKeyRead | (request.wow64_32 ? kKeyWow64Key32 : kKeyWow64Key64);
    out.win_error = ops.open_base(request.hklm_subkey, access);
    if (out.win_error != 0)
        return out;
    std::size_t total = 0;
    if (!request.each_child) {
        walk_values(request, ops, total, out.keys.emplace_back(), out.truncated);
        return out;
    }
    for (std::uint32_t index = 0;; ++index) {
        std::u16string child;
        const std::uint32_t rc = ops.child_name(index, child);
        if (rc == kErrorNoMoreItems)
            break;
        if (rc != 0) {
            out.win_error = rc;
            out.truncated = true;
            break;
        }
        if (index == kMaxRegChildren) {
            out.truncated = true;
            break;
        }
        RegKeyValues& entry = out.keys.emplace_back();
        entry.child = yuzu::shared::binary_header::utf16_to_utf8(child);
        // A child deleted since it was listed, refused, or holding a NUL (never opened) is
        // reported and the walk goes on.
        entry.win_error = has_nul(child) ? kErrorInvalidParameter : ops.open_child(child, access);
        if (entry.win_error == 0 && !walk_values(request, ops, total, entry, out.truncated))
            break;
    }
    return out;
}

} // namespace yuzu::agent::win::detail
