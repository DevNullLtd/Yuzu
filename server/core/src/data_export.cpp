#include "data_export.hpp"

#include <nlohmann/json.hpp>

namespace yuzu::server::data_export {

std::string json_array_to_csv(const std::string& json_str) {
    auto parsed = nlohmann::json::parse(json_str, nullptr, false);
    if (parsed.is_discarded() || !parsed.is_array() || parsed.empty()) {
        return {};
    }

    // Collect column names from the first object
    std::vector<std::string> columns;
    if (parsed[0].is_object()) {
        for (auto it = parsed[0].begin(); it != parsed[0].end(); ++it) {
            columns.push_back(it.key());
        }
    }
    if (columns.empty())
        return {};

    std::string csv;
    csv.reserve(json_str.size());

    // Header row
    for (size_t i = 0; i < columns.size(); ++i) {
        if (i > 0)
            csv += ',';
        csv += csv_escape(columns[i]);
    }
    csv += "\r\n";

    // Data rows
    for (const auto& row : parsed) {
        if (!row.is_object())
            continue;
        for (size_t i = 0; i < columns.size(); ++i) {
            if (i > 0)
                csv += ',';
            auto it = row.find(columns[i]);
            if (it == row.end() || it->is_null()) {
                // empty field
            } else if (it->is_string()) {
                csv += csv_escape(it->get<std::string>());
            } else {
                // Non-string cell (number, bool, object, array): quote-only.
                // neutralize_formula must NOT run here -- it would turn -5
                // into '-5 and corrupt numeric columns.
                csv += csv_quote(it->dump());
            }
        }
        csv += "\r\n";
    }

    return csv;
}

} // namespace yuzu::server::data_export
