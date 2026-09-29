// users_macos_last.hpp -- pure parsers for the macOS `last -y` last-login path.
//
// Extracted from users_plugin.cpp (qe-M1) so the timestamp/weekday logic is
// independently unit-testable without a subprocess, matching the sibling
// pattern (services_macos_launchd.hpp, bitlocker_macos_apfs.hpp,
// msi_packages_macos.hpp, event_logs_macos.hpp, filesystem_macos_sig.hpp).
// Subprocess-free and header-only; the plugin shell reads `last` and feeds
// these tokens in.
#pragma once

#include <array>
#include <format>
#include <map>
#include <string>
#include <string_view>

namespace yuzu::users_macos {

// macOS `last` reports timestamps as "Weekday Mon DD HH:MM" -- no year, no
// seconds, and (for remote sessions) an extra host column before the weekday
// whose presence isn't consistent. is_weekday finds the marker token so the
// timestamp can be located without parsing the line positionally.
inline bool is_weekday(std::string_view tok) {
    static constexpr std::array<std::string_view, 7> days = {"Sun", "Mon", "Tue", "Wed",
                                                             "Thu", "Fri", "Sat"};
    for (auto d : days) {
        if (tok == d)
            return true;
    }
    return false;
}

// Parse a `last -y`-style "Mon DD HH:MM YYYY" fragment into Windows-style
// "YYYY-MM-DD HH:MM:SS". Plain BSD `last` never reports the year, which would
// force guessing it from the current date -- wrong for any record older than
// ~12 months -- so the caller requests `-y` and this parser consumes the
// explicit year `last -y` prints instead of inferring one. Seconds are always
// ":00" since `last` doesn't report them either. Returns empty on a parse
// failure, leaving the caller's existing/"unknown"/"Never" value in place.
inline std::string parse_last_timestamp(std::string_view month_str, std::string_view day_str,
                                        std::string_view year_str, std::string_view time_str) {
    static const std::map<std::string, int> months = {
        {"Jan", 1}, {"Feb", 2}, {"Mar", 3},  {"Apr", 4},  {"May", 5},  {"Jun", 6},
        {"Jul", 7}, {"Aug", 8}, {"Sep", 9},  {"Oct", 10}, {"Nov", 11}, {"Dec", 12},
    };
    auto mit = months.find(std::string(month_str));
    if (mit == months.end())
        return {};
    int month = mit->second;

    int day = 0;
    try {
        day = std::stoi(std::string(day_str));
    } catch (...) {
        return {};
    }
    if (day < 1 || day > 31)
        return {};

    auto colon = time_str.find(':');
    if (colon == std::string_view::npos)
        return {};
    int hour = 0;
    int minute = 0;
    try {
        hour = std::stoi(std::string(time_str.substr(0, colon)));
        minute = std::stoi(std::string(time_str.substr(colon + 1)));
    } catch (...) {
        return {};
    }
    if (hour < 0 || hour > 23 || minute < 0 || minute > 59)
        return {};

    int year = 0;
    try {
        year = std::stoi(std::string(year_str));
    } catch (...) {
        return {};
    }
    if (year < 1970)
        return {};

    return std::format("{:04}-{:02}-{:02} {:02}:{:02}:00", year, month, day, hour, minute);
}

} // namespace yuzu::users_macos
