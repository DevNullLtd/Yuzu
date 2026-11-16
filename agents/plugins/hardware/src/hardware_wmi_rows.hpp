/**
 * hardware_wmi_rows.hpp -- the one set of WMI row accessors the hardware plugin uses (Windows only).
 *
 * A bounded WMI row (agents/shared/wmi_bounded.hpp) is a map of property name to string. These
 * three coercions were file-private to hardware_plugin.cpp; the estate TU needs the same rules, so
 * they live here and both include them -- two copies would drift. A missing key or an unparsable
 * number reads as ""/0, never an exception; use wmi_row_has when "absent" must be told from 0.
 */
#pragma once

#ifdef _WIN32

#include <wmi_bounded.hpp>

#include <cstdint>
#include <string>

namespace yuzu::hardware::wmi_rows {

inline std::string wmi_row_string(const yuzu::shared::wmi::WmiRow& row, const char* key) {
    const auto it = row.find(key);
    return it == row.end() ? std::string{} : it->second;
}

/// True when the property is present AND non-empty (WMI returns null properties as empty).
inline bool wmi_row_has(const yuzu::shared::wmi::WmiRow& row, const char* key) {
    return !wmi_row_string(row, key).empty();
}

inline std::uint32_t wmi_row_uint32(const yuzu::shared::wmi::WmiRow& row, const char* key) {
    const auto s = wmi_row_string(row, key);
    if (s.empty())
        return 0;
    try {
        return static_cast<std::uint32_t>(std::stoul(s));
    } catch (...) {
        return 0;
    }
}

inline std::uint64_t wmi_row_uint64(const yuzu::shared::wmi::WmiRow& row, const char* key) {
    const auto s = wmi_row_string(row, key);
    if (s.empty())
        return 0;
    try {
        return std::stoull(s);
    } catch (...) {
        return 0;
    }
}

} // namespace yuzu::hardware::wmi_rows

#endif // _WIN32
