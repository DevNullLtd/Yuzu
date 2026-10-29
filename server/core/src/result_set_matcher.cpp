#include "result_set_matcher.hpp"

#include "response_templates_engine.hpp"
#include "result_parsing.hpp"

#include <yuzu/log_token.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server::rs_matcher {

namespace {

constexpr const char* kDeclaredColumnsKey = "declared_columns";
constexpr const char* kPluginKey = "plugin";
constexpr const char* kRowDiscriminatorKey = "row_discriminator";

// Split `text` on '\n' into non-owning views, dropping a trailing empty
// fragment. Bounded by the caller's output size (responses are retention-
// capped) so no DoS surface here.
std::vector<std::string_view> split_lines(std::string_view text) {
    std::vector<std::string_view> out;
    size_t start = 0;
    while (start <= text.size()) {
        size_t nl = text.find('\n', start);
        if (nl == std::string_view::npos) {
            if (start < text.size())
                out.push_back(text.substr(start));
            break;
        }
        out.push_back(text.substr(start, nl - start));
        start = nl + 1;
    }
    return out;
}

// Split a `|`-joined echo row into cell views.
std::vector<std::string_view> split_cells(std::string_view line) {
    std::vector<std::string_view> out;
    size_t start = 0;
    while (true) {
        size_t bar = line.find('|', start);
        if (bar == std::string_view::npos) {
            out.push_back(line.substr(start));
            break;
        }
        out.push_back(line.substr(start, bar - start));
        start = bar + 1;
    }
    return out;
}

bool cell_satisfies(std::string_view cell, const std::string& op, const nlohmann::json& matcher) {
    if (op == "exists")
        return !cell.empty();
    if (op == "eq") {
        if (!matcher.contains("value") || !matcher["value"].is_string())
            return false;
        return cell == matcher["value"].get<std::string>();
    }
    if (op == "contains") {
        if (!matcher.contains("value") || !matcher["value"].is_string())
            return false;
        return cell.find(matcher["value"].get<std::string>()) != std::string_view::npos;
    }
    if (op == "in") {
        if (!matcher.contains("value_set") || !matcher["value_set"].is_array())
            return false;
        for (const auto& v : matcher["value_set"])
            if (v.is_string() && cell == v.get<std::string>())
                return true;
        return false;
    }
    return false;
}

// Column matcher over the echo `__schema__` / row / `__total__` shape. Returns
// true iff any data row's named column satisfies the op.
bool echo_column_match(std::string_view output, const std::string& column, const std::string& op,
                      const nlohmann::json& matcher) {
    auto lines = split_lines(output);
    int col_idx = -1;
    for (const auto& line : lines) {
        if (line.starts_with("__schema__")) {
            // The schema line carries a leading `__schema__` marker cell;
            // data rows do NOT. So a column at schema cell `i` (i≥1) lands at
            // data-row index `i-1`.
            auto cells = split_cells(line);
            for (size_t i = 1; i < cells.size(); ++i)
                if (cells[i] == column) {
                    col_idx = static_cast<int>(i) - 1;
                    break;
                }
            continue;
        }
        if (line.starts_with("__total__") || line.empty())
            continue;
        if (col_idx < 0)
            continue; // no schema seen yet → can't resolve the column
        auto cells = split_cells(line);
        if (static_cast<size_t>(col_idx) >= cells.size())
            continue;
        if (cell_satisfies(cells[col_idx], op, matcher))
            return true;
    }
    return false;
}

// Column matcher over a JSON array-of-objects output (`[{"sha256":"..."}]`).
// Best-effort fallback for instructions that emit structured JSON rather than
// the echo pipe format. Returns true iff any object's column satisfies the op.
bool json_column_match(std::string_view output, const std::string& column, const std::string& op,
                       const nlohmann::json& matcher) {
    auto doc = nlohmann::json::parse(output, nullptr, false);
    if (doc.is_discarded())
        return false;
    const nlohmann::json* rows = nullptr;
    if (doc.is_array())
        rows = &doc;
    else if (doc.is_object() && doc.contains("rows") && doc["rows"].is_array())
        rows = &doc["rows"];
    if (!rows)
        return false;
    for (const auto& row : *rows) {
        if (!row.is_object() || !row.contains(column))
            continue;
        const auto& field = row[column];
        std::string cell;
        if (field.is_string())
            cell = field.get<std::string>();
        else if (field.is_number_unsigned()) // before the signed case: see json_value_to_string
            cell = std::to_string(field.get<std::uint64_t>());
        else if (field.is_number_integer())
            cell = std::to_string(field.get<std::int64_t>());
        else if (field.is_number_float())
            cell = std::to_string(field.get<double>());
        else if (field.is_boolean())
            cell = field.get<bool>() ? "true" : "false";
        else
            continue;
        if (cell_satisfies(cell, op, matcher))
            return true;
    }
    return false;
}

// Column matcher over a plugin's plain pipe rows, resolved by the definition's DECLARED column
// names (stored in the matcher at admission by bind_declared_columns). By default rows are split
// exactly as the dashboard / SSE / facets split them (`split_fields`). A definition that declares
// a leading row discriminator (`discriminator: true` on its first column, stored as
// `row_discriminator`) is split on every unescaped pipe instead, so its declared columns are the
// wire fields in order; without the flag a key/value plugin's rows are key + remainder and never
// match a wider declaration. Either way a row is a data row only when its field count equals the
// declared width: a line of any other width (status|not_found, not_available|<reason>, a longer
// trailer, a malformed row) or that equals the header is skipped.
bool declared_column_match(std::string_view output, const std::string& column, const std::string& op,
                           const nlohmann::json& matcher) {
    std::vector<std::string> declared;
    for (const auto& c : matcher[kDeclaredColumnsKey])
        declared.push_back(c.get<std::string>());
    std::size_t idx = declared.size();
    for (std::size_t i = 0; i < declared.size(); ++i)
        if (declared[i] == column) {
            idx = i;
            break;
        }
    if (idx == declared.size())
        return false;
    const std::string plugin = matcher.contains(kPluginKey) ? matcher[kPluginKey].get<std::string>()
                                                            : std::string();
    const bool all_pipes = matcher.value(kRowDiscriminatorKey, false);
    for (const auto& line_view : split_lines(output)) {
        std::string line(line_view);
        if (line.empty())
            continue;
        const auto cells = all_pipes ? yuzu::server::split_all_pipes(line)
                                     : yuzu::server::split_fields(plugin, line);
        if (cells.size() != declared.size() || cells == declared)
            continue;
        if (cell_satisfies(cells[idx], op, matcher))
            return true;
    }
    return false;
}

// The `n` of an `echo_rows_ge` matcher (#4644). ABSENT is the documented default 1. A PRESENT `n`
// must be one JSON integer that fits an int; anything else (string, null, float, array, bool,
// 4294967297) is nullopt. `m.value("n", 1)` THREW on a wrong type -- out of the maintenance tick,
// where it re-threw every 2 s and starved the GC and retention reaps behind it -- and wrapped an
// out-of-range integer into a different threshold.
std::optional<int> read_row_threshold(const nlohmann::json& m) {
    if (!m.contains("n"))
        return 1;
    const auto& v = m["n"];
    if (!v.is_number_integer())
        return std::nullopt;
    if (v.is_number_unsigned()) {
        if (v.get<std::uint64_t>() > static_cast<std::uint64_t>(std::numeric_limits<int>::max()))
            return std::nullopt;
    } else {
        const auto w = v.get<std::int64_t>();
        if (w < std::numeric_limits<int>::min() || w > std::numeric_limits<int>::max())
            return std::nullopt;
    }
    return v.get<int>();
}

// A kind-less (column-shape) matcher whose column / op / value / value_set is PRESENT with the
// wrong JSON type, e.g. {"column":5,"op":"eq"}. A MISSING key is the documented "a typo cannot
// silently empty the set" fallthrough and is NOT a defect here; a present wrong-typed one used to
// fall through the same way and admit every responder, the fail-open shape the `kind` and `n`
// checks above already closed. Shared by admission and evaluation so they cannot drift.
std::optional<std::string> column_shape_defect(const nlohmann::json& m) {
    if (m.contains("column") && !m["column"].is_string())
        return "matcher.column must be a string";
    if (m.contains("op") && !m["op"].is_string())
        return "matcher.op must be a string";
    if (m.contains("value") && !m["value"].is_string())
        return "matcher.value must be a string";
    if (m.contains("value_set") && !m["value_set"].is_array())
        return "matcher.value_set must be an array";
    // Server-authored keys (bind_declared_columns). Admission refuses them from a caller outright;
    // a STORED row carrying one of the wrong type matches nobody.
    if (m.contains(kDeclaredColumnsKey)) {
        if (!m[kDeclaredColumnsKey].is_array())
            return "matcher.declared_columns must be an array of strings";
        for (const auto& c : m[kDeclaredColumnsKey])
            if (!c.is_string())
                return "matcher.declared_columns must be an array of strings";
    }
    if (m.contains(kPluginKey) && !m[kPluginKey].is_string())
        return "matcher.plugin must be a string";
    if (m.contains(kRowDiscriminatorKey) && !m[kRowDiscriminatorKey].is_boolean())
        return "matcher.row_discriminator must be a boolean";
    return std::nullopt;
}

// True when the definition's FIRST declared column carries `discriminator: true`: its columns are
// the wire fields in order, leading row-kind tag included (find_by_hash). Reads the same two
// shapes as columns_from_result_schema (array, or object with `columns`). Anything else, a stored
// definition that predates the key included, is false and keeps the plugin's own split.
bool declares_row_discriminator(const std::string& result_schema_json) {
    const auto parsed = nlohmann::json::parse(result_schema_json, nullptr, false);
    const nlohmann::json* cols = nullptr;
    if (parsed.is_array())
        cols = &parsed;
    else if (parsed.is_object() && parsed.contains("columns") && parsed["columns"].is_array())
        cols = &parsed["columns"];
    if (!cols || cols->empty() || !(*cols)[0].is_object())
        return false;
    const auto& first = (*cols)[0];
    return first.contains("discriminator") && first["discriminator"].is_boolean() &&
           first["discriminator"].get<bool>();
}

} // namespace

std::optional<std::string> validate_matcher(std::string_view matcher_json) {
    if (matcher_json.empty())
        return std::nullopt;
    const auto m = nlohmann::json::parse(matcher_json, nullptr, false);
    if (m.is_discarded() || !m.is_object())
        return std::nullopt; // the unrecognised-shape default is unchanged
    if (m.contains("kind") && !m["kind"].is_string())
        return "matcher.kind must be a string";
    for (const char* key : {kDeclaredColumnsKey, kPluginKey, kRowDiscriminatorKey})
        if (m.contains(key))
            return std::string("matcher.") + key + " is server-authored and cannot be supplied";
    if (!m.contains("kind"))
        return column_shape_defect(m);
    const auto kind = m["kind"].get<std::string>();
    // A closed set: an unknown kind would be admitted and then match nobody at evaluation
    // (below), so a stale client still sending the pre-rename `tar_rows_ge` would get a 202 and
    // an empty set indistinguishable from "no device matched". Refuse it at admission instead.
    if (kind == "any_response")
        return std::nullopt;
    // log_id_token is used here for its control-byte fold + length cap on caller input echoed
    // into the error body, not as a Guardian-id token (the SDK's safe_output_field folds only
    // backslash and CR/LF).
    if (kind != "echo_rows_ge")
        return "matcher.kind must be \"any_response\" or \"echo_rows_ge\" (got \"" +
               ::yuzu::log_id_token(kind) + "\")";
    const auto n = read_row_threshold(m);
    if (!n || *n < 1)
        return "matcher.n must be a JSON integer between 1 and 2147483647";
    return std::nullopt;
}

std::optional<std::string> validate_matcher_object(const nlohmann::json& matcher) {
    if (!matcher.is_object())
        return "matcher must be a JSON object";
    return validate_matcher(matcher.dump());
}

void bind_declared_columns(nlohmann::json& matcher, const std::string& result_schema_json,
                           const std::string& plugin) {
    if (!matcher.is_object() || matcher.contains("kind") || !matcher.contains("column") ||
        !matcher["column"].is_string())
        return;
    // Same source as the dashboard's resolve_render_columns: only a definition that DECLARES a
    // result_schema (the plugin-default fallback is a display list, not the wire layout).
    if (result_schema_json.empty())
        return;
    const auto tmpl = ResponseTemplatesEngine{}.synthesise_default(result_schema_json, plugin);
    const auto& cols = tmpl.columns;
    if (cols.empty())
        return;
    const auto column = matcher["column"].get<std::string>();
    if (std::find(cols.begin(), cols.end(), column) == cols.end())
        return;
    matcher[kDeclaredColumnsKey] = cols;
    matcher[kPluginKey] = plugin;
    if (declares_row_discriminator(result_schema_json))
        matcher[kRowDiscriminatorKey] = true;
}

int echo_row_count(std::string_view output) {
    if (output.starts_with("error|"))
        return 0;
    // Prefer the authoritative trailer the plugin emits.
    if (auto pos = output.rfind("__total__|"); pos != std::string_view::npos) {
        auto tail = output.substr(pos + std::string_view("__total__|").size());
        if (auto nl = tail.find('\n'); nl != std::string_view::npos)
            tail = tail.substr(0, nl);
        int n = 0;
        auto [ptr, ec] = std::from_chars(tail.data(), tail.data() + tail.size(), n);
        if (ec == std::errc{})
            return n;
    }
    // Fallback: count data lines (exclude schema/total/blank).
    int n = 0;
    for (const auto& line : split_lines(output)) {
        if (line.empty() || line.starts_with("__schema__") || line.starts_with("__total__"))
            continue;
        ++n;
    }
    return n;
}

bool response_matches(std::string_view matcher_json, int status, std::string_view output) {
    // A non-success response is never a hit, whatever the matcher says.
    if (status != kStatusSuccess)
        return false;

    // Empty matcher → default: any SUCCESS responder qualifies.
    if (matcher_json.empty())
        return true;
    auto m = nlohmann::json::parse(matcher_json, nullptr, false);
    if (m.is_discarded() || !m.is_object() || m.empty())
        return true;

    // A PRESENT `kind` that is not a string is malformed, not absent: it must not fall through to
    // the accept-all default below, so nobody qualifies (fail CLOSED, like an unknown kind).
    if (m.contains("kind") && !m["kind"].is_string())
        return false;

    if (m.contains("kind")) {
        const auto kind = m["kind"].get<std::string>();
        if (kind == "any_response")
            return true;
        if (kind == "echo_rows_ge") {
            // A malformed threshold fails CLOSED, like an unknown kind: nobody qualifies, and the
            // tick carries on to the next set instead of throwing. n < 1 is malformed too
            // (admission refuses it; `count >= 0` would admit every responder, a row stored
            // before that refusal included).
            const auto need = read_row_threshold(m);
            return need && *need >= 1 && echo_row_count(output) >= *need;
        }
        return false; // unknown kind → conservatively exclude
    }

    // A PRESENT but wrong-typed column / op / value / value_set is malformed, not absent: nobody
    // qualifies (admission refuses it; this covers a row stored before that refusal).
    if (column_shape_defect(m))
        return false;

    if (m.contains("column") && m["column"].is_string() && m.contains("op") && m["op"].is_string()) {
        const auto column = m["column"].get<std::string>();
        const auto op = m["op"].get<std::string>();
        // Try the echo pipe shape first (its schema line is unambiguous),
        // then the JSON array-of-objects fallback.
        if (echo_column_match(output, column, op, m) || json_column_match(output, column, op, m))
            return true;
        return m.contains(kDeclaredColumnsKey) && declared_column_match(output, column, op, m);
    }

    // Matcher present but a recognised key is MISSING (or no recognised key at all) → fall back to
    // default so a typo can't silently empty the set; the operator still gets responders.
    return true;
}

} // namespace yuzu::server::rs_matcher
