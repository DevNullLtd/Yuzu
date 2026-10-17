#include "inventory_eval.hpp"

#include "mcp_jsonrpc.hpp" // mcp::json_exceeds_depth / kMcpMaxJsonDepth: shared #2437 depth guard
#include "on_behalf_guard.hpp" // onbehalf::sanitize_for_log

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <charconv>
#include <cerrno>
#include <cmath>
#include <compare>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <optional>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>

namespace yuzu::server {

namespace {

/// Extract a value from JSON via dot-path notation.
/// Supports object keys and numeric array indices (e.g., "items.0.version").
std::optional<nlohmann::json> json_path(const nlohmann::json& root, std::string_view path) {
    const nlohmann::json* current = &root;

    while (!path.empty()) {
        auto dot = path.find('.');
        auto segment = path.substr(0, dot);
        path = (dot == std::string_view::npos) ? std::string_view{} : path.substr(dot + 1);

        if (current->is_object()) {
            std::string key{segment};
            auto it = current->find(key);
            if (it == current->end()) {
                return std::nullopt;
            }
            current = &(*it);
        } else if (current->is_array()) {
            std::size_t index = 0;
            auto [ptr, ec] = std::from_chars(segment.data(), segment.data() + segment.size(), index);
            if (ec != std::errc{} || ptr != segment.data() + segment.size()) {
                return std::nullopt;
            }
            if (index >= current->size()) {
                return std::nullopt;
            }
            current = &(*current)[index];
        } else {
            return std::nullopt;
        }
    }

    return std::optional<nlohmann::json>{*current};
}

/// Split a version string on '.' and collect numeric segments.
std::vector<int64_t> parse_version_segments(std::string_view ver) {
    std::vector<int64_t> segments;
    while (!ver.empty()) {
        auto dot = ver.find('.');
        auto part = ver.substr(0, dot);
        int64_t num = 0;
        [[maybe_unused]] auto [ptr, ec] = std::from_chars(part.data(), part.data() + part.size(), num);
        if (ec != std::errc{}) {
            num = 0;
        }
        segments.push_back(num);
        ver = (dot == std::string_view::npos) ? std::string_view{} : ver.substr(dot + 1);
    }
    return segments;
}

/// Compare two version strings lexicographically by numeric segments.
/// Returns <0 if a < b, 0 if equal, >0 if a > b.
int compare_versions(std::string_view a, std::string_view b) {
    auto segs_a = parse_version_segments(a);
    auto segs_b = parse_version_segments(b);

    auto max_len = std::max(segs_a.size(), segs_b.size());
    segs_a.resize(max_len, 0);
    segs_b.resize(max_len, 0);

    for (std::size_t i = 0; i < max_len; ++i) {
        if (segs_a[i] < segs_b[i]) return -1;
        if (segs_a[i] > segs_b[i]) return 1;
    }
    return 0;
}

/// Convert a JSON value to its string representation for comparisons and result output.
std::string json_value_to_string(const nlohmann::json& val) {
    if (val.is_string()) {
        return val.get<std::string>();
    }
    // UNSIGNED first: nlohmann's is_number_integer() is true for the unsigned variant too, and
    // get<int64_t>() wraps a stored value above INT64_MAX to a negative ("-1" for 2^64-1).
    if (val.is_number_unsigned()) {
        return std::to_string(val.get<std::uint64_t>());
    }
    if (val.is_number_integer()) {
        return std::to_string(val.get<std::int64_t>());
    }
    if (val.is_number_float()) {
        return std::to_string(val.get<double>());
    }
    if (val.is_boolean()) {
        return val.get<bool>() ? "true" : "false";
    }
    if (val.is_null()) {
        return "";
    }
    return val.dump();
}

/// True when `s` has the plain decimal shape every platform's parser agrees on: an optional '-',
/// then a digit or '.', and no 'x' / 'X'. std::from_chars refuses leading whitespace, '+' and a
/// "0x" prefix but DOES accept "inf" and "nan" (and "infinity"), and the std::stod fallback
/// (Apple Clang) is more lenient still; the shape check rejects all of those up front (a first
/// character that is not a digit or '.', and any 'x'), so a stored string means the same on every
/// OS. Applied on all platforms.
bool plain_decimal_shape(const std::string& s) {
    std::size_t i = (!s.empty() && s[0] == '-') ? 1 : 0;
    if (i >= s.size() || !((s[i] >= '0' && s[i] <= '9') || s[i] == '.'))
        return false;
    return s.find_first_of("xX") == std::string::npos;
}

/// Parse a whole string as a double; false when empty, partly consumed or out of range.
bool parse_double_full(const std::string& s, double& out) {
    if (!plain_decimal_shape(s))
        return false;
#if defined(__cpp_lib_to_chars) && __cpp_lib_to_chars >= 201611L
    const auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), out);
    return ec == std::errc{} && p == s.data() + s.size();
#else
    try {
        size_t pos = 0;
        out = std::stod(s, &pos);
        return pos == s.size();
    } catch (...) {
        return false;
    }
#endif
}

/// Parse a whole string as an integer of type T; false when empty, partly consumed or out of range.
template <typename T>
bool parse_int_full(const std::string& s, T& out) {
    const char* const end = s.data() + s.size();
    const auto [p, ec] = std::from_chars(s.data(), end, out);
    return ec == std::errc{} && p == end;
}

using Number = std::variant<std::int64_t, std::uint64_t, double>;

/// The integer digits of a whole-number decimal spelling: a '.', no exponent, nothing but '0'
/// after the '.', and at least one digit before it ("9007199254740993.0" gives "9007199254740993",
/// "-5.00" gives "-5"). False for everything else. The integer is exact where a double is not.
bool integral_decimal_digits(const std::string& s, std::string& digits) {
    const auto dot = s.find('.');
    if (dot == std::string::npos || s.find_first_of("eE") != std::string::npos ||
        s.find_first_not_of('0', dot + 1) != std::string::npos)
        return false;
    digits = s.substr(0, dot);
    return digits.find_first_of("0123456789") != std::string::npos;
}

/// The integer digits (with a leading '-' when negative) of an INTEGER-VALUED exponent spelling
/// "digits[.digits]e[+-]n" ("564141138995e7" gives "5641411389950000000", "1.50e1" gives "15",
/// "-9.223372036854775808e18" gives "-9223372036854775808"): the digits are shifted by the exponent
/// as TEXT, so no floating point is involved. False when the spelling is not that shape, when the
/// value is not a whole number ("1.25e1"), or when it needs more than 20 digits (beyond the uint64
/// range, so there is nothing exact to read); the caller then keeps the double parse. A double
/// cannot stand for such a value at 2^53 or more, which is why this is exact where it is not.
bool integral_exponent_digits(const std::string& s, std::string& digits) {
    const auto is_digit = [](char c) { return c >= '0' && c <= '9'; };
    const bool negative = !s.empty() && s[0] == '-';
    std::size_t i = negative ? 1 : 0;
    std::string mantissa;
    while (i < s.size() && is_digit(s[i]))
        mantissa.push_back(s[i++]);
    std::size_t fraction = 0;
    if (i < s.size() && s[i] == '.') {
        for (++i; i < s.size() && is_digit(s[i]); ++i, ++fraction)
            mantissa.push_back(s[i]);
    }
    if (mantissa.empty() || i >= s.size() || (s[i] != 'e' && s[i] != 'E'))
        return false;
    ++i;
    const bool exp_negative = i < s.size() && s[i] == '-';
    if (i < s.size() && (s[i] == '+' || s[i] == '-'))
        ++i;
    const std::size_t exp_start = i;
    while (i < s.size() && is_digit(s[i]))
        ++i;
    if (i != s.size() || i == exp_start)
        return false;
    const auto exp_first = s.find_first_not_of('0', exp_start);
    const std::size_t exp_digits = exp_first == std::string::npos ? 0 : s.size() - exp_first;
    if (exp_digits > 3) // beyond any value that fits 20 digits; the double path judges it
        return false;
    long exponent = 0;
    for (std::size_t k = exp_start; k < s.size(); ++k)
        exponent = exponent * 10 + (s[k] - '0');
    // value = mantissa * 10^shift, with the leading zeros of the mantissa dropped.
    const auto lead = mantissa.find_first_not_of('0');
    std::string body = lead == std::string::npos ? std::string("0") : mantissa.substr(lead);
    const long shift = (exp_negative ? -exponent : exponent) - static_cast<long>(fraction);
    if (body != "0") {
        if (shift >= 0) {
            if (body.size() + static_cast<std::size_t>(shift) > 20)
                return false;
            body.append(static_cast<std::size_t>(shift), '0');
        } else {
            const auto drop = static_cast<std::size_t>(-shift);
            if (drop >= body.size() ||
                body.find_first_not_of('0', body.size() - drop) != std::string::npos)
                return false; // a fraction remains: not a whole number
            body.resize(body.size() - drop);
        }
    }
    digits = (negative && body != "0" ? "-" : "") + body;
    return true;
}

/// A string that is a plain decimal number in full (see plain_decimal_shape: optional '-', then a
/// digit or '.', no 'x'; exponent forms such as "3e-7" count when the parse consumes them all):
/// int64, else uint64 (a whole-number spelling such as "9007199254740993.0" or an integer-valued
/// exponent spelling such as "564141138995e7" reads as the exact integer, not a rounded double),
/// else double. nullopt for anything else ("5 GB", "1.2.3", "v2",
/// " 5", "5\n", "+5", "inf", "nan", an out-of-range "1e400"). The ONE parse for a stored string
/// and for a string operand of an ordering operator.
std::optional<Number> parse_number_string(const std::string& s) {
    if (!plain_decimal_shape(s))
        return std::nullopt;
    if (std::int64_t i = 0; parse_int_full(s, i))
        return Number{i};
    if (std::uint64_t u = 0; parse_int_full(s, u))
        return Number{u};
    if (std::string digits; integral_decimal_digits(s, digits)) {
        if (std::int64_t i = 0; parse_int_full(digits, i))
            return Number{i};
        if (std::uint64_t u = 0; parse_int_full(digits, u))
            return Number{u};
    }
    if (std::string digits; integral_exponent_digits(s, digits)) {
        if (std::int64_t i = 0; parse_int_full(digits, i))
            return Number{i};
        if (std::uint64_t u = 0; parse_int_full(digits, u))
            return Number{u};
    }
    if (double d = 0.0; parse_double_full(s, d))
        return Number{d};
    return std::nullopt;
}

/// A stored JSON number, or a stored string that parses as a number in full; nullopt otherwise
/// (a non-numeric string, a boolean, an array/object: never equal to a numeric operand).
std::optional<Number> stored_number(const nlohmann::json& val) {
    if (val.is_number_unsigned())
        return Number{val.get<std::uint64_t>()};
    if (val.is_number_integer())
        return Number{val.get<std::int64_t>()};
    if (val.is_number_float())
        return Number{val.get<double>()};
    if (!val.is_string())
        return std::nullopt;
    return parse_number_string(val.get_ref<const std::string&>());
}

/// Exact integer-vs-double equality: the double must be integral and in range, then the integers
/// compare (so 9007199254740993 never equals 9007199254740992.0).
bool int_equals_double(std::int64_t i, double d) {
    return d >= -9223372036854775808.0 && d < 9223372036854775808.0 && d == std::trunc(d) &&
           static_cast<std::int64_t>(d) == i;
}
bool uint_equals_double(std::uint64_t u, double d) {
    return d >= 0.0 && d < 18446744073709551616.0 && d == std::trunc(d) &&
           static_cast<std::uint64_t>(d) == u;
}

/// `==` for two numbers: integers exactly (a negative never equals an unsigned), integer vs
/// double exactly, two doubles by exact equality.
bool numbers_equal(const Number& a, const Number& b) {
    return std::visit(
        [](const auto& x, const auto& y) -> bool {
            using X = std::decay_t<decltype(x)>;
            using Y = std::decay_t<decltype(y)>;
            if constexpr (std::is_same_v<X, Y>) {
                return x == y;
            } else if constexpr (std::is_same_v<X, double>) {
                return numbers_equal(y, x);
            } else if constexpr (std::is_same_v<Y, double>) {
                if constexpr (std::is_same_v<X, std::int64_t>)
                    return int_equals_double(x, y);
                else
                    return uint_equals_double(x, y);
            } else if constexpr (std::is_same_v<X, std::int64_t>) {
                return x >= 0 && static_cast<std::uint64_t>(x) == y;
            } else {
                return y >= 0 && static_cast<std::uint64_t>(y) == x;
            }
        },
        a, b);
}

/// Exact integer-vs-double ordering. A NaN is unordered; a double outside the integer's type range
/// orders by its sign/magnitude; inside the range the double splits into an integral part (which
/// compares as an integer, so nothing rounds through 2^53) and a fraction that breaks a tie.
std::partial_ordering order_int_double(std::int64_t i, double d) {
    if (std::isnan(d))
        return std::partial_ordering::unordered;
    if (d >= 9223372036854775808.0)
        return std::partial_ordering::less;
    if (d < -9223372036854775808.0)
        return std::partial_ordering::greater;
    const double t = std::trunc(d);
    if (const auto c = i <=> static_cast<std::int64_t>(t); c != 0)
        return c;
    const double frac = d - t;
    return frac > 0.0 ? std::partial_ordering::less
                      : (frac < 0.0 ? std::partial_ordering::greater
                                    : std::partial_ordering::equivalent);
}
std::partial_ordering order_uint_double(std::uint64_t u, double d) {
    if (std::isnan(d))
        return std::partial_ordering::unordered;
    if (d >= 18446744073709551616.0)
        return std::partial_ordering::less;
    if (d < 0.0)
        return std::partial_ordering::greater;
    const double t = std::trunc(d);
    if (const auto c = u <=> static_cast<std::uint64_t>(t); c != 0)
        return c;
    const double frac = d - t;
    return frac > 0.0 ? std::partial_ordering::less
                      : (frac < 0.0 ? std::partial_ordering::greater
                                    : std::partial_ordering::equivalent);
}

/// Three-way compare of two numbers, exact across int64 / uint64 / double (mirrors numbers_equal):
/// `unordered` only when a double is NaN. `-0` and `0` are equivalent.
std::partial_ordering compare_numbers(const Number& a, const Number& b) {
    return std::visit(
        [](const auto& x, const auto& y) -> std::partial_ordering {
            using X = std::decay_t<decltype(x)>;
            using Y = std::decay_t<decltype(y)>;
            if constexpr (std::is_same_v<X, Y>) {
                return x <=> y;
            } else if constexpr (std::is_same_v<X, double>) {
                const auto r = compare_numbers(y, x);
                if (r == std::partial_ordering::less)
                    return std::partial_ordering::greater;
                if (r == std::partial_ordering::greater)
                    return std::partial_ordering::less;
                return r;
            } else if constexpr (std::is_same_v<Y, double>) {
                if constexpr (std::is_same_v<X, std::int64_t>)
                    return order_int_double(x, y);
                else
                    return order_uint_double(x, y);
            } else if constexpr (std::is_same_v<X, std::int64_t>) {
                return x < 0 ? std::partial_ordering::less
                             : static_cast<std::uint64_t>(x) <=> y;
            } else {
                return y < 0 ? std::partial_ordering::greater
                             : x <=> static_cast<std::uint64_t>(y);
            }
        },
        a, b);
}

/// Whether an ordering `ord` of (stored, operand) satisfies the condition's `>` / `>=` / `<` / `<=`;
/// an unordered (NaN) pair never does.
bool ordering_satisfies(const InventoryCondition& cond, std::partial_ordering ord) {
    if (ord == std::partial_ordering::unordered)
        return false;
    if (cond.op == ">") return ord > 0;
    if (cond.op == ">=") return ord >= 0;
    if (cond.op == "<") return ord < 0;
    return ord <= 0;
}

/// `>` / `>=` / `<` / `<=` for a condition with a parsed numeric operand (a JSON integer, or a
/// plain-decimal string under an ordering operator): the RAW stored value (a number, or a string
/// that parses as a number in full) against the parsed operand, exactly. A stored value that is
/// not a number, or an unordered (NaN) pair, never satisfies the operator.
bool numeric_order(const nlohmann::json& stored, const InventoryCondition& cond) {
    const auto n = stored_number(stored);
    if (!n.has_value())
        return false;
    return ordering_satisfies(cond, compare_numbers(*n, cond.numeric_value));
}

/// The leading plain-decimal number of `s` (optional '-', digits, optional '.' and digits,
/// optional exponent that has at least one digit), stopping at the first character that cannot
/// continue it: "9007199254740993 B" gives "9007199254740993", "1.2.3" gives "1.2", "1e3 units"
/// gives "1e3", "5e" gives "5". The caller has already checked the first character; whether the
/// prefix is a number at all (".", "-.") is left to parse_number_string.
std::string leading_decimal_prefix(const std::string& s) {
    const auto is_digit = [](char c) { return c >= '0' && c <= '9'; };
    std::size_t i = (!s.empty() && s[0] == '-') ? 1 : 0;
    while (i < s.size() && is_digit(s[i])) ++i;
    if (i < s.size() && s[i] == '.') {
        ++i;
        while (i < s.size() && is_digit(s[i])) ++i;
    }
    if (i < s.size() && (s[i] == 'e' || s[i] == 'E')) {
        std::size_t j = i + 1;
        if (j < s.size() && (s[j] == '+' || s[j] == '-')) ++j;
        if (j < s.size() && is_digit(s[j])) {
            while (j < s.size() && is_digit(s[j])) ++j;
            i = j;
        }
    }
    return s.substr(0, i);
}

/// `==` / `!=` for a condition whose operand was a JSON number: compares the RAW stored value
/// against the parsed operand (never a rendered text, which loses digits).
bool numeric_equal(const nlohmann::json& stored, const InventoryCondition& cond) {
    const auto n = stored_number(stored);
    return n.has_value() && numbers_equal(*n, cond.numeric_value);
}

/// 2^53: below it every integer-valued double is exact; at or above it a double stands for a whole
/// range of decimals. A decimal STRING operand of this magnitude or more is refused outright
/// (subsumed for a fraction by the digit rule below, kept so the 2^53 boundary stays explicit).
constexpr double kExactDoubleLimit = 9007199254740992.0;

/// DBL_DIG: a decimal STRING of at most this many significant digits survives the round trip
/// through a double, so the rounding cannot move it across a neighbouring integer or past the next
/// stored value. A decimal of more digits ("5.00000000000000001", "4503599627370497.3") is rounded
/// by the parse, and a comparison against a stored integer can then flip.
constexpr std::size_t kMaxOperandSignificantDigits = 15;

/// The 400 / -32602 text for a decimal STRING operand the exact comparator cannot trust (see
/// operand_rounds_through_double); every clause is satisfiable by the caller.
constexpr const char* kInexactOperandMessage =
    "conditions[].value: a numeric operand must be an integer, or a decimal with at most 15 "
    "significant digits, a magnitude below 9007199254740992, not subnormal (zero is fine) and a "
    "value within the range of a double; an integer outside -9223372036854775808 to "
    "18446744073709551615 cannot be compared exactly";

/// The 400 / -32602 text for a JSON number operand that arrives as a float: written with a decimal
/// point or an exponent (5.0, 1e3, -0.0), or an integer outside the int64/uint64 range
/// (100000000000000000000 is parsed as a double). Its original text is gone once parsed, so it
/// cannot be judged exactly. Both remedies are satisfiable by the caller.
constexpr const char* kJsonFloatOperandMessage =
    "conditions[].value: a JSON number operand must be an integer within -9223372036854775808 to "
    "18446744073709551615, not a number with a decimal point or exponent, nor an integer outside "
    "that range; to compare against a decimal send it as a JSON string with an ordering operator "
    "(>, >=, <, <=)";

/// The significant digits of a decimal spelling: the digits of the mantissa (everything before an
/// 'e' / 'E'), without leading zeros and without trailing zeros ("0.0123" is 3, "5.50" is 2,
/// "1e3" is 1, "5.00000000000000001" is 18).
std::size_t significant_digits(std::string_view lexeme) {
    const auto mantissa = lexeme.substr(0, lexeme.find_first_of("eE"));
    std::string digits;
    for (const char ch : mantissa)
        if (ch >= '0' && ch <= '9')
            digits.push_back(ch);
    const auto first = digits.find_first_not_of('0');
    if (first == std::string::npos)
        return 0;
    const auto last = digits.find_last_not_of('0');
    return last - first + 1;
}

/// True for a parsed decimal STRING operand that is a double the exact comparator cannot trust: a
/// magnitude of 2^53 or more (or infinite), a non-zero magnitude below DBL_MIN (a subnormal does
/// not round-trip 15 digits and strtod implementations differ on it; zero is fine), or a lexeme of
/// more than 15 significant digits. Integers are exact and never refused here.
bool operand_rounds_through_double(const Number& n, std::string_view lexeme) {
    const double* d = std::get_if<double>(&n);
    if (d == nullptr)
        return false;
    return !(std::fabs(*d) < kExactDoubleLimit) ||
           (*d != 0.0 && std::fabs(*d) < std::numeric_limits<double>::min()) ||
           significant_digits(lexeme) > kMaxOperandSignificantDigits;
}

/// True when `s` has the plain decimal shape and a full-consumption double parse of it is out of
/// range (overflow such as "1e400", or underflow such as "1e-400"). parse_number_string returns
/// nullopt for it, and a string operand that fell out of the numeric path would silently compare
/// lexically.
bool plain_decimal_out_of_range(const std::string& s) {
    if (!plain_decimal_shape(s))
        return false;
#if defined(__cpp_lib_to_chars) && __cpp_lib_to_chars >= 201611L
    double d = 0.0;
    const auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), d);
    return ec == std::errc::result_out_of_range && p == s.data() + s.size();
#else
    // Apple Clang: no floating from_chars. strtod reports ERANGE and where it stopped.
    errno = 0;
    char* end = nullptr;
    (void)std::strtod(s.c_str(), &end);
    return errno == ERANGE && end == s.c_str() + s.size();
#endif
}

/// Evaluate a single condition against parsed JSON data.
bool eval_condition(const nlohmann::json& data, const InventoryCondition& cond,
                    std::string& matched_value_out) {
    // "exists" checks presence and non-null
    if (cond.op == "exists") {
        auto val = json_path(data, cond.field);
        if (val.has_value() && !val->is_null()) {
            matched_value_out = json_value_to_string(*val);
            return true;
        }
        return false;
    }

    auto val = json_path(data, cond.field);
    if (!val.has_value() || val->is_null()) {
        return false;
    }

    auto val_str = json_value_to_string(*val);
    matched_value_out = val_str;

    if (cond.op == "==" || cond.op == "!=") {
        const bool eq = cond.numeric_operand ? numeric_equal(*val, cond)
                                             : val_str == cond.value;
        return cond.op == "==" ? eq : !eq;
    }
    if (cond.op == "contains") return val_str.find(cond.value) != std::string::npos;

    // Version comparisons
    if (cond.op == "version_gte") return compare_versions(val_str, cond.value) >= 0;
    if (cond.op == "version_lte") return compare_versions(val_str, cond.value) <= 0;

    const bool ordering_op =
        cond.op == ">" || cond.op == ">=" || cond.op == "<" || cond.op == "<=";

    // A JSON-number operand is strict: exact numeric ordering on the raw stored value; a stored
    // value that is not a number (or a fully numeric string) never matches, never lexical and
    // never a numeric prefix.
    if (cond.numeric_operand && ordering_op)
        return numeric_order(*val, cond);

    // A string operand that is a plain decimal number is exact against a stored number or fully
    // numeric string. A stored STRING that merely starts with a number ("1.2.3", "10.0.19045",
    // "5 GB", "9007199254740993 B") compares its leading plain-decimal number through the same
    // exact parse; anything else (no numeric start, bool, array, object) never matches, never
    // lexical.
    if (cond.ordering_numeric && !cond.numeric_operand && ordering_op) {
        if (stored_number(*val).has_value())
            return numeric_order(*val, cond);
        std::size_t start = (!val_str.empty() && val_str[0] == '-') ? 1 : 0;
        if (!val->is_string() || start >= val_str.size() ||
            !((val_str[start] >= '0' && val_str[start] <= '9') || val_str[start] == '.'))
            return false;
        const auto prefix = parse_number_string(leading_decimal_prefix(val_str));
        return prefix.has_value() &&
               ordering_satisfies(cond, compare_numbers(*prefix, cond.numeric_value));
    }

    // Numeric comparisons — attempt to parse both sides as numbers
    double lhs = 0.0;
    double rhs = 0.0;
    bool lhs_ok = false, rhs_ok = false;
    // legacy_leading_number_text gives both branches the same text to read (see its comment).
    const auto lhs_text = legacy_leading_number_text(val_str);
    const auto rhs_text = legacy_leading_number_text(cond.value);
#if defined(__cpp_lib_to_chars) && __cpp_lib_to_chars >= 201611L
    if (lhs_text) {
        [[maybe_unused]] auto [lp, le] =
            std::from_chars(lhs_text->data(), lhs_text->data() + lhs_text->size(), lhs);
        lhs_ok = (le == std::errc{});
    }
    if (rhs_text) {
        [[maybe_unused]] auto [rp, re] =
            std::from_chars(rhs_text->data(), rhs_text->data() + rhs_text->size(), rhs);
        rhs_ok = (re == std::errc{});
    }
#else
    // Apple Clang fallback: std::from_chars for double may not be available. The from_chars
    // branch above reads a LEADING number (it checks only that parsing started, not that the
    // whole string was consumed), so accept a prefix here too (pos > 0): the two platforms
    // must agree on "1.2.3" < "2.0" and "5 GB" > "4" (the legacy leading-number read).
    if (lhs_text) {
        try { size_t pos = 0; lhs = std::stod(std::string(*lhs_text), &pos); lhs_ok = (pos > 0); } catch (...) {}
    }
    if (rhs_text) {
        try { size_t pos = 0; rhs = std::stod(std::string(*rhs_text), &pos); rhs_ok = (pos > 0); } catch (...) {}
    }
#endif

    if (!lhs_ok || !rhs_ok) {
        // Fall back to lexicographic comparison for non-numeric values
        if (cond.op == ">=" ) return val_str >= cond.value;
        if (cond.op == "<=" ) return val_str <= cond.value;
        if (cond.op == ">"  ) return val_str >  cond.value;
        if (cond.op == "<"  ) return val_str <  cond.value;
        return false;
    }

    if (cond.op == ">=" ) return lhs >= rhs;
    if (cond.op == "<=" ) return lhs <= rhs;
    if (cond.op == ">"  ) return lhs >  rhs;
    if (cond.op == "<"  ) return lhs <  rhs;

    return false;
}

/// #4541 review (Important finding 1): both the depth-guard and parse-error
/// exclusion paths below log once per excluded record, unconditionally - a
/// caller-controlled batch of up to the two producer routes' own
/// `limit = 5000` inventory read could pay thousands of synchronous,
/// mutex-guarded writes to the process's rotating_file_sink_mt default
/// logger on a shared httplib worker thread, for a result the two
/// durable-result-set producers discard anyway (they hard-refuse on ANY
/// non-zero exclusion count regardless of how many records excluded it).
/// Cap detailed per-record logging at this many entries PER CAUSE, per call,
/// then fold the rest into one summary line - same "+K more" shape as
/// `deprovision_revoke.cpp`'s `enumerate_principals_for_audit`
/// (kMaxEnumeratedPrincipals). Implementation detail, not a contract, so it
/// lives here rather than the header alongside kMaxInventoryConditions.
constexpr std::size_t kMaxLoggedExclusionsPerCause = 10;

} // namespace

std::optional<std::string_view> legacy_leading_number_text(std::string_view s) {
    if (!s.empty() && (s.front() == ' ' || s.front() == '+' || (s.front() >= '\t' && s.front() <= '\r')))
        return std::nullopt;
    const std::size_t digits = (!s.empty() && s.front() == '-') ? 1 : 0;
    if (s.size() >= digits + 2 && s[digits] == '0' && (s[digits + 1] == 'x' || s[digits + 1] == 'X'))
        return s.substr(0, digits + 1);
    return s;
}

std::optional<std::string> parse_inventory_condition(const nlohmann::json& c,
                                                     InventoryCondition& out) {
    if (!c.is_object())
        return "each condition must be a JSON object";
    for (const auto& [key, dest] :
         {std::pair<const char*, std::string*>{"plugin", &out.plugin},
          {"field", &out.field},
          {"op", &out.op}}) {
        if (!c.contains(key))
            continue;
        if (!c[key].is_string())
            return std::string("conditions[].") + key + " must be a JSON string";
        *dest = c[key].get<std::string>();
    }
    if (!c.contains("value"))
        return std::nullopt;
    const auto& v = c["value"];
    if (v.is_string()) {
        out.value = v.get<std::string>();
        // A string operand that is a plain decimal number orders numerically under > >= < <= only
        // (exact against a stored number; a stored string that merely starts with a number keeps
        // the legacy prefix read, see eval_condition); == / != keep the exact text compare.
        if (out.op == ">" || out.op == ">=" || out.op == "<" || out.op == "<=") {
            if (const auto n = parse_number_string(out.value)) {
                if (operand_rounds_through_double(*n, out.value))
                    return std::string(kInexactOperandMessage);
                out.ordering_numeric = true;
                out.numeric_value = *n;
            } else if (plain_decimal_out_of_range(out.value)) {
                // "1e400", a 400-digit integer, "1e-400": not a number the evaluator can hold,
                // and left as a string it would order lexically against a stored number.
                return std::string(kInexactOperandMessage);
            }
        }
        return std::nullopt;
    }
    const bool comparison = out.op == "==" || out.op == "!=" || out.op == ">" || out.op == ">=" ||
                            out.op == "<" || out.op == "<=";
    const bool equality = out.op == "==" || out.op == "!=";
    if (v.is_number() && comparison) {
        Number parsed;
        if (v.is_number_unsigned()) {
            parsed = v.get<std::uint64_t>();
        } else if (v.is_number_integer()) {
            parsed = v.get<std::int64_t>();
        } else {
            // EVERY JSON float is refused (an out-of-range integer literal arrives as one too).
            // Its original text is gone by the time it is read (5.00000000000000001 arrives as
            // 5.0, 4503599627370497.3 as ...497.0), so no rule about its digits can be applied
            // and accepting even a whole-valued one would accept lexemes whose true value differs.
            // A JSON integer is exact; a decimal goes as a string.
            return std::string(kJsonFloatOperandMessage);
        }
        out.value = v.dump();
        out.numeric_operand = true;
        out.numeric_value = parsed;
        return std::nullopt;
    }
    if (v.is_boolean() && equality) {
        out.value = v.get<bool>() ? "true" : "false";
        return std::nullopt;
    }
    return "conditions[].value must be a JSON string (a number is accepted with ==, !=, >, >=, <, "
           "<=; a boolean with == or !=)";
}

std::vector<InventoryEvalResult> evaluate_inventory(
    const InventoryEvalRequest& req,
    const std::vector<std::pair<std::string, std::string>>& records,
    std::size_t* excluded_by_depth,
    std::size_t* excluded_by_parse_error) {

    // #4496: zero the out-param up front (including on the early returns
    // below) so a caller can never read a garbage/stale count.
    if (excluded_by_depth) {
        *excluded_by_depth = 0;
    }
    // #4496 follow-up: same zero-up-front discipline for the parse-error
    // twin.
    if (excluded_by_parse_error) {
        *excluded_by_parse_error = 0;
    }

    std::vector<InventoryEvalResult> results;
    // Defense-in-depth backstop (Gate 6 sre BLOCKING fix): every caller MUST
    // reject an oversized conditions[] array before reaching here (see
    // kMaxInventoryConditions' doc comment) - this bounds the cost even if a
    // future caller forgets to.
    if (req.conditions.size() > kMaxInventoryConditions) {
        return results;
    }
    bool combine_all = (req.combine != "any");

    // #4541 review: running totals kept locally (not just via the possibly-
    // null out-param pointers) so the per-cause log cap below can gate on the
    // real count regardless of whether a given caller wants the out-param at
    // all; written through to *excluded_by_depth/*excluded_by_parse_error
    // once, after the loop.
    std::size_t depth_excluded_total = 0;
    std::size_t parse_error_excluded_total = 0;

    for (const auto& [key, data_json] : records) {
        // Parse the composite key: "agent_id|plugin"
        auto sep = key.find('|');
        if (sep == std::string::npos) {
            continue;
        }
        auto record_agent_id = key.substr(0, sep);
        auto record_plugin = key.substr(sep + 1);

        // If the request targets a specific agent, skip non-matching records
        if (!req.agent_id.empty() && record_agent_id != req.agent_id) {
            continue;
        }

        // #2437-class guard: data_json is the same generic ADR-0016 blob read by
        // data_inventory_routes.cpp (see its own guard for the write-side
        // context) - reached here via all three evaluate_inventory() callers,
        // the REST /api/v1/inventory/evaluate route, the REST
        // from-inventory-query result-set producer, and the MCP
        // create_result_set_from_inventory_query tool. json::parse handles very
        // deep input fine (the catch below guards a genuine parse error, not
        // this), but json_value_to_string's dump() fallback on the parsed tree
        // is unboundedly recursive - a too-deep record would SIGSEGV the whole
        // process for every caller at once. Check the raw text before parse and
        // skip this record exactly like a genuine parse error, below. Log
        // identifiers only, never the payload. #4496: count the exclusion so
        // callers can signal an incomplete result rather than silently
        // returning fewer matches than actually exist. #4541 review: capped
        // at kMaxLoggedExclusionsPerCause detailed lines (see its doc
        // comment) - this guard predates the cap (shipped in #4478/#4496),
        // retrofitted here once the review caught the identical unbounded
        // shape on the parse-error sibling below.
        if (mcp::json_exceeds_depth(data_json, mcp::kMcpMaxJsonDepth)) {
            ++depth_excluded_total;
            if (depth_excluded_total <= kMaxLoggedExclusionsPerCause) {
                spdlog::warn("evaluate_inventory: excluding agent={} plugin={} - data_json nests "
                            "too deeply (#2437-class)",
                            onbehalf::sanitize_for_log(record_agent_id, 128),
                            onbehalf::sanitize_for_log(record_plugin, 128));
            }
            continue;
        }

        nlohmann::json data;
        try {
            data = nlohmann::json::parse(data_json);
        } catch (const nlohmann::json::parse_error&) {
            // #4496 follow-up: a genuinely malformed data_json (syntax
            // defect, not over-nesting - the depth guard above already
            // excluded the latter) is the SAME "excluded from evaluation"
            // hazard #4496 fixed, triggered by a different cause. Count it
            // separately from excluded_by_depth so a caller can tell WHICH
            // guard excluded a record. Log identifiers only, never the
            // payload. #4541 review: same per-cause cap as the depth guard
            // above, for the identical reason (an unbounded per-record
            // spdlog::warn here was Important finding 1 on the PR review that
            // added this branch).
            ++parse_error_excluded_total;
            if (parse_error_excluded_total <= kMaxLoggedExclusionsPerCause) {
                spdlog::warn("evaluate_inventory: excluding agent={} plugin={} - data_json failed "
                            "to parse (malformed JSON)",
                            onbehalf::sanitize_for_log(record_agent_id, 128),
                            onbehalf::sanitize_for_log(record_plugin, 128));
            }
            continue;
        }

        bool overall_match = combine_all;  // true for AND, false for OR
        std::string last_matched_value;

        for (const auto& cond : req.conditions) {
            // If condition specifies a plugin, skip records from other plugins
            if (!cond.plugin.empty() && cond.plugin != record_plugin) {
                if (combine_all) {
                    overall_match = false;
                    break;
                }
                continue;
            }

            std::string matched_value;
            bool cond_result = eval_condition(data, cond, matched_value);

            if (cond_result) {
                last_matched_value = matched_value;
            }

            if (combine_all) {
                if (!cond_result) {
                    overall_match = false;
                    break;
                }
            } else {
                if (cond_result) {
                    overall_match = true;
                    break;
                }
            }
        }

        if (overall_match) {
            int64_t collected_at = 0;
            if (data.contains("collected_at") && data["collected_at"].is_number_integer() &&
                (!data["collected_at"].is_number_unsigned() ||
                 data["collected_at"].get<std::uint64_t>() <=
                     static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))) {
                // An unsigned above INT64_MAX is not an epoch int64 can hold: leave 0, don't wrap.
                collected_at = data["collected_at"].get<int64_t>();
            }

            results.push_back(InventoryEvalResult{
                .agent_id = record_agent_id,
                .match = true,
                .matched_value = last_matched_value,
                .plugin = record_plugin,
                .collected_at = collected_at,
            });
        }
    }

    // #4541 review: fold whatever the per-cause cap above suppressed into one
    // summary line each, so the total exclusion volume for this call stays
    // visible in the log even though the per-record detail was capped.
    if (depth_excluded_total > kMaxLoggedExclusionsPerCause) {
        spdlog::warn("evaluate_inventory: suppressed {} further depth-guard exclusion log "
                    "lines ({} excluded total this call)",
                    depth_excluded_total - kMaxLoggedExclusionsPerCause, depth_excluded_total);
    }
    if (parse_error_excluded_total > kMaxLoggedExclusionsPerCause) {
        spdlog::warn("evaluate_inventory: suppressed {} further parse-error exclusion log "
                    "lines ({} excluded total this call)",
                    parse_error_excluded_total - kMaxLoggedExclusionsPerCause,
                    parse_error_excluded_total);
    }
    if (excluded_by_depth) {
        *excluded_by_depth = depth_excluded_total;
    }
    if (excluded_by_parse_error) {
        *excluded_by_parse_error = parse_error_excluded_total;
    }

    return results;
}

} // namespace yuzu::server
