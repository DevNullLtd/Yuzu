#pragma once

#include <nlohmann/json_fwd.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
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
    /// kept for display): two integers compare exactly (signed and unsigned mixed correctly), a
    /// stored integer against a double (a stored double, or an ordering-string operand) compares
    /// exactly (the integer part as an integer, then the fraction), and two doubles compare as
    /// doubles (`-0` equals `0`). A JSON operand is exact only as an
    /// integer (every JSON float is refused, see parse_inventory_condition: its original text is
    /// gone once parsed); a decimal is sent as a string with an ordering operator
    /// (`ordering_numeric`), which admits a whole number within int64/uint64 (digits, or an
    /// integer-valued exponent form such as "1e16", read exactly) or at most 15 significant digits;
    /// a whole number up to the uint64 range is sent as an integer. A STORED double above 2^53 is whatever
    /// the agent reported. A stored string that parses
    /// in full as a number counts as that number (stored "10.0" equals operand 10, stored "10" is
    /// greater than operand 9). A stored integer within int64/uint64 (including an integer-valued
    /// exponent spelling that fits, such as "564141138995e7") and a stored decimal with a fraction
    /// of at most 15 significant digits and a magnitude below 2^53 compare exactly; any other stored
    /// decimal (more digits, or a non-integer at or above 2^53) compares as the nearest double, as
    /// does a stored negative integer below -9223372036854775808. Any other stored value (non-numeric string such as "5 GB" or "N/A",
    /// boolean, array) is never equal and never satisfies an ordering operator: a JSON number
    /// operand is strict, with no numeric-prefix tolerance. A string operand
    /// keeps the exact lexical `==` / `!=` (so "1.10" and "1.1" stay different); for the ordering
    /// operators see `ordering_numeric`.
    bool numeric_operand = false;
    /// True when the caller's `value` was a STRING that is a plain decimal number in full (optional
    /// '-', a digit or '.', no 'x'; exponent forms such as "2e-7" count; set by
    /// parse_inventory_condition, ordering operators `>` `>=` `<` `<=` only). Against a stored
    /// number or fully numeric string the ordering operators compare exactly (to the limits stated
    /// on `numeric_operand`), like a JSON-number operand. Unlike a JSON-number operand this one
    /// tolerates a stored STRING that merely starts with a number: its leading plain-decimal number
    /// (optional '-', digits, optional fraction, optional exponent) goes through the same exact
    /// parse and compare (dotted version "1.2.3" reads as 1.2, "5 GB" as 5, "9007199254740993 B" as
    /// that exact integer), so devices that matched before keep matching; any other stored value (no
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
/// refused. A number used to become "": `{"op":">","value":5}` then selected EVERY device that had the
/// field, because the evaluator falls back to a lexicographic compare against the empty string.
/// EVERY JSON float operand is refused (anything written with a decimal point or exponent: 5.0,
/// 1e3, -0.0, non-finite; an integer literal outside int64/uint64 arrives as a float too): its original text is gone once parsed (5.00000000000000001 arrives as
/// 5.0), so even a whole-valued one would accept lexemes whose true value differs. JSON integers
/// (signed and unsigned) are exact. The caller sends a decimal as a string under `>` `>=` `<` `<=`.
/// A decimal STRING under those operators that would be rounded through a double is refused: one
/// that is not a whole number and has more than 15 significant digits (digits after leading zeros
/// and trailing zeros; "5.00000000000000001" and "4503599627370497.3" round to a neighbour), a
/// magnitude of 2^53 or more that is not a whole number within int64/uint64 (a whole number is
/// read exactly and exempt), a non-zero subnormal ("1e-320": it does not round-trip and strtod
/// differs by OS; zero is fine), or a value outside the double range ("1e400", "1e-400", which
/// would otherwise fall to a lexical compare). `==` / `!=` with a string stay a text compare, so a
/// non-integer decimal cannot be matched for equality numerically.
/// A whole number is sent as an integer of any size up to the int64/uint64 range, or as a digit
/// string, which reads as that exact integer (also with a zero fraction, "9007199254740993.0", or
/// as an integer-valued exponent form that fits, "564141138995e7" or "1e16").
/// Returns the 400 / -32602 message, or nullopt when accepted (`out` is then filled in).
[[nodiscard]] std::optional<std::string> parse_inventory_condition(const nlohmann::json& c,
                                                                   InventoryCondition& out);

/// The text a legacy leading-number read (the ordering fallback for a non-plain-decimal string
/// operand, see eval_condition) hands to the number parser, so the std::from_chars path and the
/// std::stod fallback (Apple Clang) read the same number: nullopt when from_chars would refuse the
/// first character (leading whitespace or '+'), the text up to and including the '0' for a "0x" /
/// "0X" prefix (from_chars reads the zero and stops at the 'x'; stod would read hex), else the
/// text unchanged. Applied on every platform, so it is testable on Linux.
[[nodiscard]] std::optional<std::string_view> legacy_leading_number_text(std::string_view s);

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
