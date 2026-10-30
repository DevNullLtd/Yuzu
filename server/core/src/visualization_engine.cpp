#include "visualization_engine.hpp"

#include "result_parsing.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstdio>
#include <map>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace yuzu::server {

namespace {

using nlohmann::json;

// ── JSON output helpers ──────────────────────────────────────────────────
//
// Direct string building (no nlohmann::json::dump) so the engine produces
// the same shape the rest_api_v1.cpp JObj/JArr builders use without pulling
// those private helpers across translation-unit boundaries. A 5-line
// escape function is a smaller cross-cutting concern than dragging the
// builder header into a public include.

void json_escape(std::string& out, std::string_view sv) {
    out.reserve(out.size() + sv.size());
    for (char c : sv) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char hex[8];
                    std::snprintf(hex, sizeof(hex), "\\u%04x",
                                  static_cast<unsigned int>(static_cast<unsigned char>(c)));
                    out += hex;
                } else {
                    out += c;
                }
        }
    }
}

std::string quote_str(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 2);
    out += '"';
    json_escape(out, s);
    out += '"';
    return out;
}

/// Emit a number for a chart axis. `nan` and `inf` collapse to 0 — the JS
/// renderer would skip-and-warn on `null`, but treating non-finite values
/// as 0 is closer to operator intent ("count the rows that didn't parse")
/// without breaking the SVG path generator on the client.
std::string fmt_number(double v) {
    if (!std::isfinite(v)) return "0";
    if (std::trunc(v) == v && std::fabs(v) < 1e15) {
        return std::to_string(static_cast<long long>(v));
    }
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.6g", v);
    return buf;
}

std::string error_payload(std::string_view message) {
    std::string out = "{\"error\":";
    out += quote_str(message);
    out += '}';
    return out;
}

// ── Spec parsing ─────────────────────────────────────────────────────────

constexpr std::string_view kValidTypes[] = {"pie", "bar", "column", "line", "area"};
constexpr std::string_view kValidProcessors[] = {"single_series", "multi_series",
                                                  "datetime_series"};

bool is_valid_type(std::string_view t) {
    for (auto v : kValidTypes)
        if (v == t) return true;
    return false;
}

bool is_valid_processor(std::string_view p) {
    for (auto v : kValidProcessors)
        if (v == p) return true;
    return false;
}

/// Resolve a spec key, preferring the canonical camelCase form and falling
/// back to the snake_case form as a legacy alias. Yuzu's YAML DSL convention
/// is camelCase (`gatherTtlSeconds`, `responseTtlDays`, `displayName`); the
/// snake_case names were used during issue #253's first round (governance
/// finding dsl-B2) and are accepted as deprecated aliases so existing
/// in-flight definitions don't break.
const json* resolve_key(const json& obj, std::string_view camel,
                        std::string_view snake) {
    if (auto it = obj.find(camel); it != obj.end()) return &*it;
    if (auto it = obj.find(snake); it != obj.end()) return &*it;
    return nullptr;
}

/// Field references in the spec are stored as 0-based indices into the
/// per-plugin column schema, EXCLUDING the leading "Agent" column. So
/// `labelField=0` for plugin `processes` means the "PID" column, not
/// "Agent". `-1` means "unspecified".
int parse_field_index(const json& obj, std::string_view camel,
                      std::string_view snake) {
    auto* v = resolve_key(obj, camel, snake);
    if (!v || v->is_null()) return -1;
    if (v->is_number_integer()) return v->get<int>();
    return -1;
}

/// Optional row pre-filter so a single chart can isolate one logical
/// "category" of rows from a plugin that emits a mixed key|value layout.
/// Example: antivirus emits `realtime_protection|enabled`,
/// `definition_version|...`, `last_update|...` rows for a single device —
/// charting "real-time protection across the fleet" needs whereField=0
/// whereEquals="realtime_protection" to filter to just the relevant rows
/// before labelField=1 picks the value.
///
/// `where_field == -1` means "no filter". `where_value` is matched
/// case-sensitively against the exact field contents (no glob, no regex).
struct WhereSpec {
    int where_field{-1};
    std::string where_value;
    [[nodiscard]] bool active() const noexcept { return where_field >= 0; }
    [[nodiscard]] bool matches(const std::vector<std::string>& fields) const {
        if (!active()) return true;
        // Reuse field_or_empty semantics so out-of-range columns just fail
        // the match (rather than throwing) — keeps the engine forgiving on
        // mixed-shape outputs.
        if (where_field >= static_cast<int>(fields.size())) return false;
        return fields[where_field] == where_value;
    }
};

WhereSpec parse_where_spec(const json& obj) {
    WhereSpec w;
    w.where_field = parse_field_index(obj, "whereField", "where_field");
    if (auto* v = resolve_key(obj, "whereEquals", "where_equals");
        v && v->is_string()) {
        w.where_value = v->get<std::string>();
    }
    // Defensive: if whereField was given but whereEquals wasn't (or vice
    // versa), disable the filter rather than half-apply it. Half-config
    // is almost always an authoring mistake and silently letting either
    // half through would make the chart non-deterministic.
    if (w.where_field >= 0 && w.where_value.empty()) w.where_field = -1;
    if (w.where_field < 0)                          w.where_value.clear();
    return w;
}

/// `x_field` for datetime_series accepts either a numeric index or the
/// literal string "agent_timestamp" — meaning "use the response's wall-
/// clock timestamp instead of a column value". This matches the way most
/// agents emit data: a single point per response, plotted along time.
struct DateTimeXField {
    bool from_response_timestamp{false};
    int col_idx{-1};
};

DateTimeXField parse_x_field(const json& obj) {
    DateTimeXField r;
    auto* v = resolve_key(obj, "xField", "x_field");
    if (!v || v->is_null()) {
        r.from_response_timestamp = true; // sensible default
        return r;
    }
    if (v->is_string()) {
        if (v->get<std::string>() == "agent_timestamp")
            r.from_response_timestamp = true;
        return r;
    }
    if (v->is_number_integer())
        r.col_idx = v->get<int>();
    return r;
}

/// Read a field at `idx` from a parsed-output row. Returns the empty string
/// for out-of-range indices (defensive: a schema mismatch between spec and
/// plugin should not crash the renderer, just produce an empty bucket).
std::string field_or_empty(const std::vector<std::string>& fields, int idx) {
    if (idx < 0 || idx >= static_cast<int>(fields.size())) return {};
    return fields[idx];
}

double to_number_or_one(std::string_view s) {
    // Treat empty / non-numeric as 1 so "count rows" semantics work when the
    // spec declares value_field but a row's value is non-numeric (e.g. "n/a").
    // Operator-facing: matches the Excel-like behaviour of "if it doesn't
    // parse as a number, count the row instead".
    if (s.empty()) return 1.0;
    // std::from_chars(double) lacks coverage on Apple Clang 15; cel_eval.cpp
    // and inventory_eval.cpp use the same #if guard. Without it macOS CI
    // fails to compile (governance bld-B1).
#if defined(__cpp_lib_to_chars) && __cpp_lib_to_chars >= 201611L
    double out = 0.0;
    auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), out);
    if (ec != std::errc{} || ptr != s.data() + s.size()) return 1.0;
    return out;
#else
    try {
        std::size_t pos = 0;
        double out = std::stod(std::string{s}, &pos);
        if (pos != s.size()) return 1.0;
        return out;
    } catch (...) {
        return 1.0;
    }
#endif
}

// Engine-side hard cap on distinct labels (governance F-9 / sec-M4 / UP-4).
// A spec author can ask for `max_categories` to control display, but the cap
// here protects the server from a 1M-distinct-label response set blowing
// out memory regardless of spec. Larger than any legitimate human-facing
// chart but small enough to bound a std::map<string,double>'s working set.
constexpr int kEngineLabelHardCap = 10000;

// ── Single-series processor (Pie / Bar / Column / Line / Area) ──────────
//
// Walks every response, splits its output into rows, groups by the
// `label_field` value, and either counts rows or sums `value_field`.
// Output: a single series named after `value_label` (default "Count").

struct LabelTotal {
    std::string label;
    double total{0.0};
};

std::vector<LabelTotal>
group_single(const std::string& plugin, int label_field, int value_field,
             const WhereSpec& where,
             const std::vector<StoredResponse>& responses) {
    // Use std::map for deterministic ordering — operator dashboards benefit
    // from a stable label sequence across reruns. The label cardinality is
    // bounded by the response set so the O(log n) cost is negligible.
    std::map<std::string, double> totals;
    for (const auto& r : responses) {
        if (r.output.empty()) continue;
        for (const auto& line : split_output_lines(r.output)) {
            if (is_echo_protocol_line(line)) continue;
            auto fields = split_fields(plugin, line);
            if (!where.matches(fields)) continue;
            auto label = field_or_empty(fields, label_field);
            if (label.empty()) continue;
            double inc = (value_field >= 0)
                             ? to_number_or_one(field_or_empty(fields, value_field))
                             : 1.0;
            // Hard cap on label cardinality. Existing labels keep
            // accumulating; new ones are dropped once the cap is hit.
            if (totals.size() >= kEngineLabelHardCap && !totals.contains(label))
                continue;
            totals[label] += inc;
        }
    }
    std::vector<LabelTotal> out;
    out.reserve(totals.size());
    for (auto& [k, v] : totals) out.push_back({k, v});
    return out;
}

/// Apply a top-N cap. Anything beyond the cap is collapsed into a single
/// "Other" bucket so a tail of singletons doesn't blow out the legend.
void apply_max_categories(std::vector<LabelTotal>& buckets, int max_n) {
    if (max_n <= 0 || static_cast<int>(buckets.size()) <= max_n) return;
    std::partial_sort(buckets.begin(), buckets.begin() + max_n, buckets.end(),
                      [](const LabelTotal& a, const LabelTotal& b) {
                          return a.total > b.total;
                      });
    double other = 0.0;
    for (size_t i = max_n; i < buckets.size(); ++i) other += buckets[i].total;
    buckets.resize(max_n);
    if (other > 0) buckets.push_back({"Other", other});
}

// ── Multi-series processor ──────────────────────────────────────────────

std::vector<LabelTotal>
group_multi(const std::string& plugin, int label_field, int series_field, int value_field,
            const WhereSpec& where,
            const std::vector<StoredResponse>& responses,
            std::map<std::string, std::map<std::string, double>>& by_series) {
    // Two-level grouping: series name → label → total. The single-pass walk
    // builds both the per-series totals and a stable label ordering by
    // recording the first-seen position of each label.
    std::vector<std::string> label_order;
    std::unordered_set<std::string> seen;
    for (const auto& r : responses) {
        if (r.output.empty()) continue;
        for (const auto& line : split_output_lines(r.output)) {
            if (is_echo_protocol_line(line)) continue;
            auto fields = split_fields(plugin, line);
            if (!where.matches(fields)) continue;
            auto label = field_or_empty(fields, label_field);
            auto series = field_or_empty(fields, series_field);
            if (label.empty() || series.empty()) continue;
            double inc = (value_field >= 0)
                             ? to_number_or_one(field_or_empty(fields, value_field))
                             : 1.0;
            // Hard cap on (label × series) cartesian — sec-M4 / F-9.
            bool new_label = !seen.contains(label);
            bool new_series = !by_series.contains(series);
            if ((new_label && seen.size() >= kEngineLabelHardCap) ||
                (new_series && by_series.size() >= kEngineLabelHardCap))
                continue;
            by_series[series][label] += inc;
            if (seen.insert(label).second) label_order.push_back(label);
        }
    }
    // Caller wants `LabelTotal` for the ordered axis labels; series-level
    // data is filled in by the caller from `by_series` against this order.
    std::vector<LabelTotal> out;
    out.reserve(label_order.size());
    for (auto& l : label_order) out.push_back({l, 0.0});
    return out;
}

// ── Datetime-series processor ───────────────────────────────────────────

struct DtPoint {
    int64_t x{0};
    double y{0.0};
};

void render_datetime_series(const json& spec, const std::string& plugin,
                             const std::vector<StoredResponse>& responses,
                             std::string& out) {
    auto x_field = parse_x_field(spec);
    int y_field = parse_field_index(spec, "yField", "y_field");
    int series_field = parse_field_index(spec, "seriesField", "series_field");

    // series name → (x → y). map<int64_t,double> keeps the points sorted by
    // x. Multiple data points at the same x within one series are summed —
    // matches "events per second" / "errors per minute" semantics.
    std::map<std::string, std::map<int64_t, double>> series;

    for (const auto& r : responses) {
        if (r.output.empty()) continue;
        for (const auto& line : split_output_lines(r.output)) {
            if (is_echo_protocol_line(line)) continue;
            auto fields = split_fields(plugin, line);
            int64_t x_val = 0;
            if (x_field.from_response_timestamp) {
                x_val = r.timestamp;
            } else {
                auto raw = field_or_empty(fields, x_field.col_idx);
                if (raw.empty()) continue;
                int64_t parsed = 0;
                [[maybe_unused]] auto [ptr, ec] = std::from_chars(raw.data(), raw.data() + raw.size(), parsed);
                if (ec != std::errc{}) continue;
                x_val = parsed;
            }
            double y_val = (y_field >= 0)
                               ? to_number_or_one(field_or_empty(fields, y_field))
                               : 1.0;
            std::string sname =
                (series_field >= 0) ? field_or_empty(fields, series_field) : r.agent_id;
            if (sname.empty()) sname = "(unlabeled)";
            // sec-M4 / F-9: cap series cardinality on datetime processor too.
            if (series.size() >= kEngineLabelHardCap && !series.contains(sname))
                continue;
            series[sname][x_val] += y_val;
        }
    }

    // Build a unioned, sorted x-axis so every series has a value at every
    // tick (filling missing points with 0). This avoids the JS renderer
    // having to align disparate per-series x ranges.
    std::vector<int64_t> x_axis;
    {
        std::map<int64_t, bool> all_x;
        for (const auto& [_, pts] : series)
            for (const auto& [x, _y] : pts) all_x[x] = true;
        x_axis.reserve(all_x.size());
        for (auto& [x, _] : all_x) x_axis.push_back(x);
    }

    out += "\"x_axis\":\"datetime\",\"x\":[";
    for (size_t i = 0; i < x_axis.size(); ++i) {
        if (i) out += ',';
        out += std::to_string(x_axis[i]);
    }
    out += "],\"series\":[";

    bool first = true;
    for (const auto& [name, pts] : series) {
        if (!first) out += ',';
        first = false;
        out += "{\"name\":";
        out += quote_str(name);
        out += ",\"data\":[";
        for (size_t i = 0; i < x_axis.size(); ++i) {
            if (i) out += ',';
            auto it = pts.find(x_axis[i]);
            out += fmt_number(it == pts.end() ? 0.0 : it->second);
        }
        out += "]}";
    }
    out += "]";
}

// ── Single / multi labels+series rendering ──────────────────────────────

void render_labels_array(const std::vector<LabelTotal>& buckets, std::string& out) {
    out += "\"labels\":[";
    for (size_t i = 0; i < buckets.size(); ++i) {
        if (i) out += ',';
        out += quote_str(buckets[i].label);
    }
    out += "]";
}

void render_single_series(const json& spec, const std::string& plugin,
                           const std::vector<StoredResponse>& responses, std::string& out) {
    int label_field = parse_field_index(spec, "labelField", "label_field");
    int value_field = parse_field_index(spec, "valueField", "value_field");
    int max_n = parse_field_index(spec, "maxCategories", "max_categories");
    auto where = parse_where_spec(spec);
    if (label_field < 0) label_field = 0; // sensible default

    auto buckets = group_single(plugin, label_field, value_field, where, responses);
    apply_max_categories(buckets, max_n);

    std::string series_name = "Count";
    if (auto* v = resolve_key(spec, "valueLabel", "value_label"); v && v->is_string())
        series_name = v->get<std::string>();

    render_labels_array(buckets, out);
    out += ",\"series\":[{\"name\":";
    out += quote_str(series_name);
    out += ",\"data\":[";
    for (size_t i = 0; i < buckets.size(); ++i) {
        if (i) out += ',';
        out += fmt_number(buckets[i].total);
    }
    out += "]}]";
}

void render_multi_series(const json& spec, const std::string& plugin,
                          const std::vector<StoredResponse>& responses, std::string& out) {
    int label_field = parse_field_index(spec, "labelField", "label_field");
    int series_field = parse_field_index(spec, "seriesField", "series_field");
    int value_field = parse_field_index(spec, "valueField", "value_field");
    auto where = parse_where_spec(spec);
    if (label_field < 0) label_field = 0;
    if (series_field < 0) series_field = 1;

    std::map<std::string, std::map<std::string, double>> by_series;
    auto labels = group_multi(plugin, label_field, series_field, value_field, where,
                              responses, by_series);

    render_labels_array(labels, out);
    out += ",\"series\":[";
    bool first = true;
    for (const auto& [name, label_totals] : by_series) {
        if (!first) out += ',';
        first = false;
        out += "{\"name\":";
        out += quote_str(name);
        out += ",\"data\":[";
        for (size_t i = 0; i < labels.size(); ++i) {
            if (i) out += ',';
            auto it = label_totals.find(labels[i].label);
            out += fmt_number(it == label_totals.end() ? 0.0 : it->second);
        }
        out += "]}";
    }
    out += "]";
}

// ── Top-level dispatcher ─────────────────────────────────────────────────

void render_meta(const std::vector<StoredResponse>& responses, std::string& out) {
    // Operators triaging an empty chart need to know whether the issue is
    // "no rows came back" vs "rows came back but the spec produced nothing"
    // — emit both counts so the dashboard can label the empty state.
    int succeeded = 0;
    int failed = 0;
    for (const auto& r : responses) {
        if (r.status == 0) ++succeeded;
        else ++failed;
    }
    out += "\"meta\":{";
    out += "\"responses_total\":" + std::to_string(responses.size());
    out += ",\"responses_succeeded\":" + std::to_string(succeeded);
    out += ",\"responses_failed\":" + std::to_string(failed);
    out += "}";
}

/// True if @p chart is a JSON object that looks like a complete
/// visualization spec (has `type` + `processor`). Used to filter the array
/// shape so a stray null / empty object inside `visualizations: [...]`
/// doesn't count as a configured chart.
bool is_chart_object(const json& chart) {
    return chart.is_object() && chart.contains("type") && chart.contains("processor");
}

/// Resolve the chart at @p index from @p spec_json. Returns std::nullopt
/// when no chart exists at that index. Tolerates both shapes:
///   * legacy singular: `{"type": "...", ...}` — index 0 is the object,
///     all other indices are out of range
///   * canonical array: `[{...}, {...}]` — index 0..N-1 valid
std::optional<json> chart_at(std::string_view spec_json, int index) {
    if (spec_json.empty() || index < 0) return std::nullopt;
    auto parsed = json::parse(spec_json, nullptr, false);
    if (parsed.is_discarded()) return std::nullopt;
    // nlohmann::json has aggressive implicit conversions, so wrapping a
    // json into std::optional<json> with `return chart;` is ambiguous —
    // be explicit with std::make_optional.
    if (parsed.is_array()) {
        if (index >= static_cast<int>(parsed.size())) return std::nullopt;
        const auto& chart = parsed[static_cast<std::size_t>(index)];
        if (!is_chart_object(chart)) return std::nullopt;
        return std::make_optional<json>(chart);
    }
    if (parsed.is_object()) {
        if (index != 0 || !is_chart_object(parsed)) return std::nullopt;
        return std::make_optional<json>(parsed);
    }
    return std::nullopt;
}

VisualizationEngine::Result render_chart(const json& spec, const std::string& plugin,
                                          const std::vector<StoredResponse>& responses) {
    auto type = spec.value("type", std::string{});
    auto processor = spec.value("processor", std::string{});
    if (!is_valid_type(type)) {
        return {false, error_payload("invalid chart type: " + type)};
    }
    if (!is_valid_processor(processor)) {
        return {false, error_payload("invalid processor: " + processor)};
    }

    std::string out;
    out.reserve(1024);
    out += '{';
    out += "\"chart_type\":";
    out += quote_str(type);

    if (spec.contains("title") && spec["title"].is_string()) {
        out += ",\"title\":";
        out += quote_str(spec["title"].get<std::string>());
    }

    out += ',';
    if (processor == "single_series") {
        render_single_series(spec, plugin, responses, out);
    } else if (processor == "multi_series") {
        render_multi_series(spec, plugin, responses, out);
    } else if (processor == "datetime_series") {
        render_datetime_series(spec, plugin, responses, out);
    } else {
        return {false, error_payload("unknown processor: " + processor)};
    }

    out += ',';
    render_meta(responses, out);
    out += '}';

    return {true, std::move(out)};
}

} // anonymous namespace

bool VisualizationEngine::has_visualization(std::string_view spec_json) {
    return count(spec_json) > 0;
}

int VisualizationEngine::count(std::string_view spec_json) {
    if (spec_json.empty()) return 0;
    auto parsed = json::parse(spec_json, nullptr, false);
    if (parsed.is_discarded()) return 0;
    if (parsed.is_array()) {
        int n = 0;
        for (const auto& c : parsed)
            if (is_chart_object(c)) ++n;
        return n;
    }
    if (parsed.is_object() && is_chart_object(parsed)) return 1;
    return 0;
}

VisualizationEngine::Result
VisualizationEngine::transform_at(std::string_view spec_json, int index,
                                   const std::string& plugin,
                                   const std::vector<StoredResponse>& responses) const {
    if (count(spec_json) == 0) {
        return {false, error_payload("no visualization configured")};
    }
    auto chart = chart_at(spec_json, index);
    if (!chart) {
        return {false, error_payload("visualization index out of range")};
    }
    return render_chart(*chart, plugin, responses);
}

VisualizationEngine::Result
VisualizationEngine::transform(std::string_view spec_json, const std::string& plugin,
                                const std::vector<StoredResponse>& responses) const {
    return transform_at(spec_json, 0, plugin, responses);
}

} // namespace yuzu::server
