#include "quantified_matcher.hpp"

#include "result_parsing.hpp"
#include "result_set_matcher.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <charconv>
#include <limits>

namespace yuzu::server::rs_matcher {
namespace {
using Json = nlohmann::json;

bool recognized_kind(std::string_view kind) {
    return kind == "any" || kind == "none" || kind == "all" || kind == "count_where";
}

std::optional<std::string> check_predicate(const Json& expr, unsigned depth, unsigned& remaining) {
    if (remaining == 0)
        return "matcher.where exceeds 64 predicates";
    --remaining;
    if (depth > 16)
        return "matcher.where exceeds 16 levels";
    if (!expr.is_object())
        return "matcher.where requires a row predicate object";
    for (const char* key : {"not", "and", "or"}) {
        if (!expr.contains(key))
            continue;
        if (expr.size() != 1)
            return "a boolean row predicate must contain exactly one operator";
        const auto& arg = expr.at(key);
        if (std::string_view(key) == "not")
            return check_predicate(arg, depth + 1, remaining);
        if (!arg.is_array() || arg.empty())
            return "and/or require a nonempty array of row predicates";
        for (const auto& child : arg)
            if (auto error = check_predicate(child, depth + 1, remaining))
                return error;
        return std::nullopt;
    }
    for (const auto& [key, val] : expr.items())
        if (key != "column" && key != "op" && key != "value" && key != "value_set")
            return "unknown key in row predicate";
    if (!expr.contains("column") || !expr["column"].is_string() ||
        expr["column"].get_ref<const std::string&>().empty() || !expr.contains("op") ||
        !expr["op"].is_string())
        return "a row test needs a nonempty column and an operator";
    const auto& op = expr["op"].get_ref<const std::string&>();
    if (expr["column"].get_ref<const std::string&>().size() > kMatcherColumnMaxBytes ||
        op.size() > kMatcherOpMaxBytes)
        return std::string(kMatcherFieldTooLargeMessage);
    if (op == "exists" && expr.size() == 2)
        return std::nullopt;
    if ((op == "eq" || op == "contains") && expr.size() == 3 && expr.contains("value") &&
        expr["value"].is_string()) {
        if (expr["value"].get_ref<const std::string&>().size() > kMatcherValueMaxBytes)
            return std::string(kMatcherFieldTooLargeMessage);
        return std::nullopt;
    }
    if (op == "in" && expr.size() == 3 && expr.contains("value_set") &&
        expr["value_set"].is_array()) {
        for (const auto& value : expr["value_set"]) {
            if (!value.is_string())
                return "matcher.value_set entries must be strings";
            if (value.get_ref<const std::string&>().size() > kMatcherValueMaxBytes)
                return std::string(kMatcherFieldTooLargeMessage);
        }
        return std::nullopt;
    }
    return "invalid row predicate operator or operand";
}

bool unknown(RowMatch value) {
    return value != RowMatch::True && value != RowMatch::False;
}

RowMatch invert(RowMatch v) {
    if (v == RowMatch::True)
        return RowMatch::False;
    return v == RowMatch::False ? RowMatch::True : v;
}

RowMatch combine_cause(RowMatch prior, RowMatch next) {
    if (prior == RowMatch::MissingValue || !unknown(next))
        return prior;
    return next;
}

struct Counts {
    std::size_t yes{}, no{}, undecided{};
    RowMatch cause{RowMatch::False};
    void add(RowMatch answer) {
        if (answer == RowMatch::True)
            ++yes;
        else if (answer == RowMatch::False)
            ++no;
        else {
            ++undecided;
            cause = combine_cause(cause, answer);
        }
    }
    std::size_t size() const { return yes + no + undecided; }
};

RowMatch compare_range(const std::string& op, std::uint64_t threshold, std::uint64_t lo,
                       std::uint64_t hi, RowMatch cause) {
    const auto truth = [](bool result) {
        return result ? RowMatch::True : RowMatch::False;
    };
    if (op == "eq") {
        if (threshold < lo || threshold > hi)
            return RowMatch::False;
        return lo == hi ? RowMatch::True : cause;
    }
    const auto satisfies = [&](std::uint64_t value) {
        if (op == "lt")
            return value < threshold;
        if (op == "le")
            return value <= threshold;
        if (op == "gt")
            return value > threshold;
        return value >= threshold;
    };
    return satisfies(lo) == satisfies(hi) ? truth(satisfies(lo)) : cause;
}

std::vector<std::string> split_echo_cells(std::string_view line) {
    std::vector<std::string> cells;
    while (true) {
        auto bar = line.find('|');
        cells.emplace_back(line.substr(0, bar));
        if (bar == line.npos)
            return cells;
        line.remove_prefix(bar + 1);
    }
}
} // namespace

bool is_quantified_matcher(const Json& matcher) {
    return matcher.is_object() && matcher.contains("kind") && matcher["kind"].is_string() &&
           recognized_kind(matcher["kind"].get_ref<const std::string&>());
}

std::optional<std::string> validate_quantified_matcher(const Json& m) {
    for (const auto& [key, value] : m.items()) {
        if (key != "kind" && key != "where" && key != "op" && key != "n" &&
            key != "declared_columns" && key != "row_discriminator" && key != "plugin" &&
            key != "partial_when_constrained")
            return "unknown key in quantified matcher";
    }
    if (!m.contains("where"))
        return "quantified matcher requires where";
    if (m.at("kind") == "count_where") {
        if (!m.contains("op") || !m["op"].is_string() || !m.contains("n") ||
            !m["n"].is_number_integer() ||
            (!m["n"].is_number_unsigned() && m["n"].get<int64_t>() < 0))
            return "count_where needs a nonnegative integer n and an eq/lt/le/gt/ge operator";
        const auto& op = m["op"];
        if (op != "eq" && op != "lt" && op != "le" && op != "gt" && op != "ge")
            return "count_where.op must be eq, lt, le, gt or ge";
        if (m["n"].get<std::uint64_t>() >
            static_cast<std::uint64_t>(std::numeric_limits<int64_t>::max()))
            return "count_where.n exceeds the signed integer range";
    } else if (m.contains("op") || m.contains("n"))
        return "only count_where takes op and n";
    unsigned remaining = 64;
    return check_predicate(m.at("where"), 1, remaining);
}

QuantifiedMatcher::Predicate::Predicate(const Json& expr) {
    if (expr.contains("not")) {
        kind = Kind::Not;
        children.emplace_back(expr.at("not"));
    } else if (expr.contains("and") || expr.contains("or")) {
        kind = expr.contains("and") ? Kind::And : Kind::Or;
        for (const auto& child : expr.at(kind == Kind::And ? "and" : "or"))
            children.emplace_back(child);
    } else {
        column = expr.at("column").get<std::string>();
        op = expr.at("op").get<std::string>();
        if (expr.contains("value"))
            value = expr.at("value").get<std::string>();
        if (expr.contains("value_set"))
            for (const auto& entry : expr.at("value_set"))
                values.emplace(entry.get_ref<const std::string&>());
    }
}

RowMatch QuantifiedMatcher::Predicate::evaluate(const Json& row) const {
    if (kind == Kind::Not)
        return invert(children.front().evaluate(row));
    if (kind != Kind::Leaf) {
        const auto decisive = kind == Kind::And ? RowMatch::False : RowMatch::True;
        auto answer = invert(decisive);
        for (const auto& child : children) {
            const auto v = child.evaluate(row);
            if (v == decisive)
                return v;
            answer = combine_cause(answer, v);
        }
        return answer;
    }
    if (!row.is_object())
        return RowMatch::MalformedValue;
    const auto it = row.find(column);
    if (it == row.end() || it->is_null())
        return RowMatch::MissingValue;
    if (!it->is_primitive())
        return RowMatch::MalformedValue;
    // Match the existing JSON column grammar's numeric-to-text conversion.
    std::string converted;
    std::string_view cell;
    if (it->is_string())
        cell = it->get_ref<const std::string&>();
    else {
        converted = it->is_number_float() ? std::to_string(it->get<double>()) : it->dump();
        cell = converted;
    }
    bool matched = op == "exists"     ? !cell.empty()
                   : op == "eq"       ? cell == value
                   : op == "contains" ? cell.find(value) != cell.npos
                                      : values.contains(cell);
    return matched ? RowMatch::True : RowMatch::False;
}

QuantifiedMatcher::QuantifiedMatcher(const Json& matcher)
    : matcher_(matcher), where_(matcher.at("where")) {}

RowMatch QuantifiedMatcher::evaluate(std::string_view output, bool complete) const {
    Counts counts;
    RowMatch open_end = complete ? RowMatch::False : RowMatch::CoverageUnproven;
    if (output.starts_with("error|"))
        return RowMatch::MalformedValue;
    const auto first = output.find_first_not_of(" \r\t\n");
    if (first != output.npos && (output[first] == '[' || output[first] == '{')) {
        const auto doc = Json::parse(output, nullptr, false);
        const auto* rows = &doc;
        if (doc.is_object() && doc.contains("rows"))
            rows = &doc.at("rows");
        if (!rows->is_array())
            return RowMatch::MalformedValue;
        for (const auto& row : *rows) {
            if (counts.size() == kQuantifiedRowLimit) {
                open_end = RowMatch::RowBound;
                break;
            }
            counts.add(where_.evaluate(row));
        }
    } else {
        const bool bound = matcher_.contains("declared_columns");
        std::vector<std::string> columns;
        if (bound)
            columns = matcher_.at("declared_columns").get<std::vector<std::string>>();
        std::uint64_t observed = 0;
        bool echo = false;
        std::optional<std::uint64_t> total_rows;
        while (!output.empty()) {
            const auto end = output.find('\n');
            auto line = output.substr(0, end);
            if (line.ends_with('\r'))
                line.remove_suffix(1);
            output.remove_prefix(end == output.npos ? output.size() : end + 1);
            if (line.empty() && !echo)
                continue;
            if (total_rows)
                return RowMatch::MalformedValue;
            if (line.starts_with("__schema__|")) {
                if (echo || counts.size())
                    return RowMatch::MalformedValue;
                echo = true;
                columns = split_echo_cells(line.substr(11));
                continue;
            }
            if (line.starts_with("__total__|")) {
                const auto total = line.substr(10);
                std::uint64_t n{};
                const auto [ptr, err] =
                    std::from_chars(total.data(), total.data() + total.size(), n);
                if (err != std::errc{} || ptr != total.data() + total.size())
                    return RowMatch::MalformedValue;
                if (!echo || n < observed)
                    return RowMatch::MalformedValue;
                total_rows = n;
                if (n > observed)
                    open_end = RowMatch::RowBound;
                continue;
            }
            if (columns.empty())
                return RowMatch::MissingValue;
            ++observed;
            if (counts.size() == kQuantifiedRowLimit) {
                open_end = RowMatch::RowBound;
                continue; // verify the trailing count even after stopping row evaluation
            }
            auto cells =
                echo ? split_echo_cells(line)
                : matcher_.value("row_discriminator", false)
                    ? split_all_pipes(std::string(line))
                    : split_fields(matcher_.value("plugin", std::string{}), std::string(line));
            if (!echo && cells == columns)
                continue;
            if (cells.size() != columns.size()) {
                counts.add(RowMatch::MalformedValue);
                continue;
            }
            auto row = Json::object();
            for (std::size_t i = 0; i < std::min(cells.size(), columns.size()); ++i)
                if (!echo || !cells[i].empty())
                    row.emplace(columns[i], std::move(cells[i]));
            counts.add(where_.evaluate(row));
        }
        if (columns.empty())
            return RowMatch::MissingValue;
        if (!echo && !unknown(open_end))
            open_end = RowMatch::CoverageUnproven;
        if (echo && counts.size() >= kQuantifiedRowLimit)
            open_end = RowMatch::RowBound;
        if (echo && !total_rows && open_end != RowMatch::RowBound)
            open_end = RowMatch::CoverageUnproven;
    }
    const auto& kind = matcher_.at("kind").get_ref<const std::string&>();
    if (kind == "count_where") {
        const auto& op = matcher_.at("op").get_ref<const std::string&>();
        const auto n = matcher_.at("n").get<std::uint64_t>();
        const auto limited =
            compare_range(op, n, counts.yes, counts.yes + counts.undecided, counts.cause);
        if (!unknown(open_end))
            return limited;
        const auto wide =
            compare_range(op, n, counts.yes, std::numeric_limits<std::uint64_t>::max(), open_end);
        // The unbounded tail supplies the cause only when it changed a definite answer.
        return unknown(wide) && unknown(limited) ? limited : wide;
    }
    if (kind == "all" && counts.no)
        return RowMatch::False;
    if (kind != "all" && counts.yes)
        return kind == "none" ? RowMatch::False : RowMatch::True;
    if (unknown(open_end))
        return open_end;
    if (counts.undecided)
        return counts.cause;
    return kind == "any" ? RowMatch::False : RowMatch::True;
}

} // namespace yuzu::server::rs_matcher
