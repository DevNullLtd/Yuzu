/**
 * wmi_rows.hpp -- the PURE row formatters for the wmi plugin (portable: no COM,
 * no platform header, unit-tested on every OS).
 *
 * WMI property names and string values are endpoint-controlled (for example
 * Win32_Process.CommandLine is settable by any local user). The wire format is
 * pipe-delimited, one record per line, so BOTH the key and the value go through
 * yuzu::shared::row_field: a '|', CR or LF cannot add columns or forge
 * rows. Interior backslashes are kept (`C:\x` stays `C:\x`); a trailing one folds
 * to '/' so it cannot glue onto the delimiter (yuzu::shared::row_field).
 */
#pragma once

#include <row_field.hpp>

#include <string>
#include <string_view>

namespace yuzu::wmi {

/// `row<N>|<key>|<value>` (wmi.query).
[[nodiscard]] inline std::string format_row_line(int row, std::string_view key,
                                                 std::string_view value) {
    return "row" + std::to_string(row) + "|" + yuzu::shared::row_field(key) + "|" +
           yuzu::shared::row_field(value);
}

/// `property|<key>|<value>` (wmi.get_instance).
[[nodiscard]] inline std::string format_property_line(std::string_view key,
                                                      std::string_view value) {
    return "property|" + yuzu::shared::row_field(key) + "|" +
           yuzu::shared::row_field(value);
}

} // namespace yuzu::wmi
