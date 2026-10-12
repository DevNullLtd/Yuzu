#pragma once

#include <nlohmann/json_fwd.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace yuzu::server {

struct InventoryCondition {
    std::string plugin;
    std::string field;
    std::string op;    // "==", "!=", ">=", "<=", ">", "<", "contains", "exists", "version_gte", "version_lte"
    std::string value;
    /// True only when the caller's JSON `value` was a number (set by parse_inventory_condition).
    /// `==` / `!=` / `>` / `>=` / `<` / `<=` then compare the RAW stored value against
    /// `numeric_value`, the operand as the caller sent it, never against `value` (the `dump()` text,
    /// kept for display): two integers compare exactly (signed and unsigned mixed correctly), an
    /// integer against a double compares exactly with no rounding through 2^53, and two doubles
    /// compare as doubles (`0.1 + 0.2` is not `0.3`, `-0` equals `0`). A stored string that parses
    /// in full as a number counts as that number (stored "1.10" equals operand 1.1, stored "10" is
    /// greater than operand 9); any other stored value (non-numeric string such as "5 GB" or "N/A",
    /// boolean, array) is never equal and never satisfies an ordering operator: a JSON number
    /// operand is strict, with no numeric-prefix tolerance. A string operand
    /// keeps the exact lexical `==` / `!=` (so "1.10" and "1.1" stay different); for the ordering
    /// operators see `ordering_numeric`.
    bool numeric_operand = false;
    /// True when the caller's `value` was a STRING that is a plain decimal number in full (optional
    /// '-', a digit or '.', no 'x'; exponent forms such as "2e-7" count; set by
    /// parse_inventory_condition, ordering operators `>` `>=` `<` `<=` only). Against a stored
    /// number or fully numeric string the ordering operators compare exactly, like a JSON-number
    /// operand. Unlike a JSON-number operand this one tolerates the legacy leading-number read of a
    /// stored STRING that merely starts with a number (dotted version "1.2.3" reads as 1.2,
    /// "5 GB" as 5), so devices that matched before keep matching; any other stored value (no
    /// numeric start such as "N/A", "" or "v2.1", boolean, array, object) never satisfies the
    /// operators, never a lexical compare. Dotted versions belong with `version_gte` /
    /// `version_lte`. `==` / `!=` are unaffected (exact text compare). A string operand that is not
    /// a plain decimal number ("abc", "1.2.3", "v2", " 5", "5 GB") keeps the legacy
    /// numeric-prefix-then-lexical ordering.
    bool ordering_numeric = false;
    /// The parsed operand; meaningful only when `numeric_operand` or `ordering_numeric` is set.
    std::variant<std::int64_t, std::uint64_t, double> numeric_value = std::int64_t{0};
};

/// Build one InventoryCondition from a caller's `conditions[]` element (#4644). The ONE copy for
/// REST `POST /api/v1/inventory/evaluate`, REST `POST /api/v1/result-sets/from-inventory-query`
/// and MCP `create_result_set_from_inventory_query`; a second copy is how the three drifted.
///
/// ABSENT keys keep the empty default. A PRESENT `plugin` / `field` / `op` must be a JSON string.
/// A PRESENT `value` is the string itself, or, for a comparison operator (`==`, `!=`, `>`, `>=`,
/// `<`, `<=`), a JSON number kept as its `dump()` text plus the parsed number in `numeric_value`,
/// with `numeric_operand` set (so all six operators compare it numerically against the raw stored
/// value, exact for integers and for integer vs double), or a boolean as `true` / `false` for
/// `==` / `!=` only. Anything else (null, array, object, a number under another operator) is
/// refused. It used
/// to become "": `{"op":">","value":5}` then selected EVERY device that had the field, because the
/// evaluator falls back to a lexicographic compare against the empty string.
/// Returns the 400 / -32602 message, or nullopt when accepted (`out` is then filled in).
[[nodiscard]] std::optional<std::string> parse_inventory_condition(const nlohmann::json& c,
                                                                   InventoryCondition& out);

struct InventoryEvalRequest {
    std::string agent_id;
    std::vector<InventoryCondition> conditions;
    std::string combine = "all";  // "all" (AND) or "any" (OR)
};

/// Gate 6 sre BLOCKING fix (#2146 Batch B2 review): evaluate_inventory() is
/// O(conditions x records) with the "any" combine mode's short-circuit
/// trivially defeated by conditions that never match, so an uncapped
/// conditions[] array lets a single request pin a worker thread on the
/// shared httplib pool for an unbounded time - every caller (both
/// create_result_set_from_inventory_query transports, plus the pre-existing
/// POST /api/v1/inventory/evaluate) MUST reject a conditions[] array larger
/// than this before calling evaluate_inventory(). A few hundred is generous
/// for any real query; conditions are per-field predicates, not device IDs
/// (device_ids' own 100000-item cap is the wrong analog).
inline constexpr std::size_t kMaxInventoryConditions = 500;

struct InventoryEvalResult {
    std::string agent_id;
    bool match;
    std::string matched_value;
    std::string plugin;
    int64_t collected_at;
};

/// Evaluate inventory conditions against a set of records.
/// @param req              The evaluation request specifying agent, conditions, and combine mode.
/// @param records          A vector of (agent_id + "|" + plugin, data_json) pairs.
/// @param excluded_by_depth
///        Optional out-parameter (issue #4496), same idiom as
///        `InventoryStore::query`'s `bool* truncated`. When non-null, set to
///        the count of input records skipped because their `data_json`
///        nested past `kMcpMaxJsonDepth` (the #2437-class poison-exclusion
///        guard) - NOT records skipped for a genuine JSON parse error, which
///        is counted separately by `excluded_by_parse_error` below. A
///        non-zero count means the returned results may be missing matches
///        the caller cannot detect any other way; every production caller
///        must surface this signal (flag it in the response, or refuse to
///        act on a narrowed target set - see the three call sites for which
///        posture each took).
/// @param excluded_by_parse_error
///        Optional out-parameter (issue #4496 follow-up), same idiom as
///        `excluded_by_depth` above and default-nullptr for the same reason
///        (every pre-existing call site stays source-compatible). When
///        non-null, set to the count of input records skipped because their
///        `data_json` failed to parse as JSON at all (a syntax defect, not
///        over-nesting - a different failure cause than `excluded_by_depth`,
///        counted separately so an operator debugging missing results can
///        tell WHICH guard excluded a record). A non-zero count carries the
///        same "results may be missing matches" implication as
///        `excluded_by_depth` and every production caller must surface it
///        the same way.
/// @return          Results for agents whose inventory matches the request conditions.
std::vector<InventoryEvalResult> evaluate_inventory(
    const InventoryEvalRequest& req,
    const std::vector<std::pair<std::string, std::string>>& records,
    std::size_t* excluded_by_depth = nullptr,
    std::size_t* excluded_by_parse_error = nullptr);

} // namespace yuzu::server
