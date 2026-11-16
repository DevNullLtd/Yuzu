#pragma once

/// @file json_value_budget.hpp
///
/// The ONE raw-text counter of structural JSON values, shared by the body-cap chokepoint
/// (`body_cap_policy.hpp` / `step_up_wiring.hpp`, which applies a per-route-class budget to every
/// request body) and the definition import/authoring code (`instruction_definition_model.hpp`,
/// which applies its own budget to bodies and to JSON-encoded string fields).
///
/// Why a count and not only a size cap: nlohmann::json builds roughly 30 to 100 bytes per value, so
/// a body of `[],[],...` becomes a parse tree 16 to 27 times its own size (258 to 429 MiB for
/// 16 MiB, measured), and eight concurrent ones were enough to get a process killed for exceeding a
/// 2 GB memory limit. The depth guard (`mcp::json_exceeds_depth`) does not bound breadth.
///
/// The scan runs on the raw text BEFORE any parse, so the tree it protects against is never built.
/// It counts `[`, `{` and `,` outside string literals (escapes honoured), which bounds the number of
/// values: every non-root value is preceded by an opener or a comma. It does not validate JSON, and
/// like `mcp::json_exceeds_depth` it cannot see inside a string literal, so a JSON-encoded STRING
/// field that is re-parsed later needs its own call on its own text.

#include <cstddef>
#include <string_view>

namespace yuzu::server {

/// True when `body` holds more than `max_values` structural values. Linear, allocation-free.
[[nodiscard]] constexpr bool json_exceeds_value_count(std::string_view body,
                                                      std::size_t max_values) noexcept {
    std::size_t values = 0;
    bool in_string = false;
    bool escaped = false;
    for (const char c : body) {
        if (in_string) {
            if (escaped)
                escaped = false;
            else if (c == '\\')
                escaped = true;
            else if (c == '"')
                in_string = false;
            continue;
        }
        switch (c) {
        case '"':
            in_string = true;
            break;
        case '[':
        case '{':
        case ',':
            if (++values > max_values)
                return true;
            break;
        default:
            break;
        }
    }
    return false;
}

} // namespace yuzu::server
