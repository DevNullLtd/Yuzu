// inventory_status_row.hpp -- the one definition of the inventory `status` row.
//
// Every inventory action that feeds the installed-software collector
// (pkg_inventory.managers / packages / store_packages and
// msi_packages.list_inventory) answers with exactly one leading
//
//   status|<action>|<supported|constrained|unsupported>|<tokens or ->
//
// row followed by its data rows. This header owns that grammar in both
// directions so the producers and the consumer cannot drift:
//
//   - PRODUCER: format_status_row (pkg_inventory and msi_packages call it).
//   - CONSUMER: is_status_line / parse_status_row (the collector,
//     agents/core/src/sync_source_installed_software.cpp, calls them).
//
// What lives here: the field positions, the level vocabulary, the `>= 4
// fields` and `same action` rules. What does NOT: line splitting (the
// collector splits on the raw '|' and hands over tokens), and what a level
// MEANS for a cycle -- that is the collector's per-action policy table
// (ConstrainedPolicy), so parse_status_row returns field 4 at every level and
// the caller decides whether it surfaces as a reason.
//
// ESCAPING. Free text goes through yuzu::util::safe_output_field, which is
// DOCUMENTED LOSSY (sdk/include/yuzu/string_utils.hpp): a literal backslash
// folds to '/', CR and LF fold to ' ', and a '|' is written as `\|`. The
// consumer splits on the raw '|' and does not unescape, so a token containing
// '|' is cut at the escaped pipe. Both are pre-existing wire behaviour, pinned
// by tests/unit/test_inventory_status_row.cpp; they are NOT defects to repair
// here -- changing the formatter would change the bytes the plugins emit.
//
// Platform-agnostic, header-only, no OS call. Call sites use it fully
// qualified (`yuzu::shared::format_status_row`), the convention of this
// directory (see constraint_accumulator.hpp).
#pragma once

#include <yuzu/string_utils.hpp>

#include <initializer_list>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace yuzu::shared {

enum class StatusLevel { supported, constrained, unsupported };

/// The wire token of a level. The default arm is `constrained`: an
/// out-of-range value reads as "could not be fully read", never as supported.
[[nodiscard]] constexpr std::string_view status_level_token(StatusLevel l) noexcept {
    switch (l) {
    case StatusLevel::supported:
        return "supported";
    case StatusLevel::constrained:
        return "constrained";
    case StatusLevel::unsupported:
        return "unsupported";
    }
    return "constrained";
}

/// Inverse of status_level_token over the three wire tokens; anything else
/// (including the empty string, other case and surrounding whitespace) is
/// nullopt.
[[nodiscard]] constexpr std::optional<StatusLevel>
status_level_from_token(std::string_view t) noexcept {
    for (const StatusLevel l :
         {StatusLevel::supported, StatusLevel::constrained, StatusLevel::unsupported}) {
        if (t == status_level_token(l))
            return l;
    }
    return std::nullopt;
}

/// status|<action>|<level>|<tokens or ->. Takes already-computed values and
/// returns the row WITHOUT a trailing newline. An empty `tokens` is written as
/// "-"; `action` and `tokens` go through safe_output_field.
[[nodiscard]] inline std::string format_status_row(std::string_view action, StatusLevel level,
                                                   std::string_view tokens) {
    std::string out = "status|";
    out += yuzu::util::safe_output_field(action);
    out += '|';
    out += status_level_token(level);
    out += '|';
    out += tokens.empty() ? std::string{"-"} : yuzu::util::safe_output_field(tokens);
    return out;
}

/// True when the (already split) line is a status line at all, whatever action
/// or width. A status line is consumed by the status grammar and never offered
/// to a data-row parser.
[[nodiscard]] constexpr bool is_status_line(std::span<const std::string_view> tok) noexcept {
    return !tok.empty() && tok[0] == "status";
}

/// A parsed status row. `level` is nullopt for an unknown level token: the row
/// still counts as THE status row of its action (a bad level is a bad status,
/// not a missing one). `tokens` is field 4 verbatim at every level.
struct StatusRow {
    std::optional<StatusLevel> level;
    std::string tokens;
};

/// Reads a status line for `action`. nullopt when the line is not a status line,
/// has fewer than four fields, or answers a different action -- such a line is
/// not counted. Fields past the fourth are ignored.
[[nodiscard]] inline std::optional<StatusRow>
parse_status_row(std::span<const std::string_view> tok, std::string_view action) {
    if (!is_status_line(tok) || tok.size() < 4 || tok[1] != action)
        return std::nullopt;
    return StatusRow{status_level_from_token(tok[2]), std::string(tok[3])};
}

} // namespace yuzu::shared
