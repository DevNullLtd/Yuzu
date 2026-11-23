/**
 * row_field.hpp -- the backslash-PRESERVING row-field escaper shared by the
 * filesystem, procfetch, wmi, installed_apps and network_config plugins
 * (owner ruling on #5208, WP11). Hoisted from filesystem's
 * yuzu::filesystem::acl::row_field, which now forwards here: EXTEND, never fork.
 *
 * One field of a pipe-delimited, newline-separated result row:
 *   - CR and LF fold to a space, so a value cannot start a new row;
 *   - '|' becomes `\|` (the server decoder's only escape), so it cannot add a column;
 *   - interior backslashes are KEPT (`C:\x` stays `C:\x`), unlike
 *     yuzu::util::safe_output_field, which folds every backslash to '/' and is
 *     left unchanged for its many other callers;
 *   - a TRAILING backslash folds to '/': the server decoder
 *     (result_parsing.hpp find_unescaped_pipe) reads `\|` as an escaped pipe, so a
 *     field ending in '\' would glue onto the delimiter and merge with the next
 *     column.
 * The processes plugin keeps its own space-fold of '|' (its consumers split the
 * rows on a raw '|') but applies the same trailing-backslash rule.
 */
#pragma once

#include <yuzu/string_utils.hpp>

#include <string>
#include <string_view>

namespace yuzu::shared {

[[nodiscard]] inline std::string row_field(std::string_view value) {
    std::string out;
    out.reserve(value.size());
    for (const char ch : value)
        out += (ch == '\r' || ch == '\n') ? ' ' : ch;
    if (!out.empty() && out.back() == '\\')
        out.back() = '/';
    return yuzu::util::escape_pipes(out);
}

} // namespace yuzu::shared
