/**
 * wmi_rows.hpp -- the PURE row formatters for the wmi plugin (portable: no COM,
 * no platform header, unit-tested on every OS).
 *
 * WMI property names and string values are endpoint-controlled (for example
 * Win32_Process.CommandLine is settable by any local user). The wire format is
 * pipe-delimited, one record per line, so BOTH the key and the value go through
 * yuzu::util::safe_output_field: a '|', CR or LF cannot add columns or forge
 * rows. A literal backslash folds to '/' (the shared escaper's documented lossy
 * contract, see #5208) -- the same treatment the registry/printing plugins give
 * their free text.
 */
#pragma once

#include <yuzu/string_utils.hpp>

#include <string>
#include <string_view>

namespace yuzu::wmi {

/// `row<N>|<key>|<value>` (wmi.query).
[[nodiscard]] inline std::string format_row_line(int row, std::string_view key,
                                                 std::string_view value) {
    return "row" + std::to_string(row) + "|" + yuzu::util::safe_output_field(key) + "|" +
           yuzu::util::safe_output_field(value);
}

/// `property|<key>|<value>` (wmi.get_instance).
[[nodiscard]] inline std::string format_property_line(std::string_view key,
                                                      std::string_view value) {
    return "property|" + yuzu::util::safe_output_field(key) + "|" +
           yuzu::util::safe_output_field(value);
}

} // namespace yuzu::wmi
